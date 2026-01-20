"""
SnapshotManager - Block-level Copy-on-Write micro-snapshotting system.

This module implements a CoW mechanism that:
1. Saves original data blocks before any write operation
2. Compresses snapshots using zlib to save memory/disk space
3. Maintains block-level granularity (not file-level)
4. Enables file reconstruction from saved snapshots
"""

import zlib
import time
import threading
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
from collections import defaultdict
from pathlib import Path
import hashlib


# Default block size for snapshotting (4KB, typical filesystem block)
DEFAULT_BLOCK_SIZE = 4096

# Compression level (1-9, higher = smaller but slower)
COMPRESSION_LEVEL = 6

# Maximum memory for snapshots (512MB default)
DEFAULT_MAX_MEMORY_BYTES = 512 * 1024 * 1024


@dataclass
class CompressedBlock:
    """
    Represents a compressed snapshot of a data block.
    
    Attributes:
        compressed_data: zlib-compressed original data
        original_size: Size of data before compression
        offset: Block offset within the file
        timestamp: When this snapshot was created
        checksum: SHA-256 hash of original data for integrity verification
    """
    compressed_data: bytes
    original_size: int
    offset: int
    timestamp: float
    checksum: str  # SHA-256 hex digest
    
    @property
    def compressed_size(self) -> int:
        """Size of compressed data."""
        return len(self.compressed_data)
    
    @property
    def compression_ratio(self) -> float:
        """Ratio of compressed to original size."""
        if self.original_size == 0:
            return 1.0
        return self.compressed_size / self.original_size
    
    def decompress(self) -> bytes:
        """Decompress and return original data."""
        data = zlib.decompress(self.compressed_data)
        # Verify integrity
        if hashlib.sha256(data).hexdigest() != self.checksum:
            raise ValueError(f"Block integrity check failed at offset {self.offset}")
        return data


@dataclass
class FileSnapshot:
    """
    Collection of block snapshots for a single file.
    
    Maintains all saved blocks for a file, enabling full reconstruction.
    """
    inode: int
    path: str
    blocks: Dict[int, CompressedBlock] = field(default_factory=dict)  # offset -> block
    original_size: int = 0
    created_at: float = field(default_factory=time.time)
    last_modified: float = field(default_factory=time.time)
    
    @property
    def total_compressed_size(self) -> int:
        """Total compressed size of all blocks."""
        return sum(b.compressed_size for b in self.blocks.values())
    
    @property
    def total_original_size(self) -> int:
        """Total original size of all blocks."""
        return sum(b.original_size for b in self.blocks.values())
    
    @property
    def block_count(self) -> int:
        """Number of saved blocks."""
        return len(self.blocks)


class SnapshotManager:
    """
    Manages block-level Copy-on-Write snapshots.
    
    This implements the defense mechanism that saves original data before
    potentially malicious writes, enabling recovery if ransomware is detected.
    
    Architecture:
    - Snapshots are stored in memory (dict structure) by default
    - Optional shadow storage directory for persistence
    - Blocks are compressed with zlib to reduce memory footprint
    - LRU eviction when memory limit is reached
    """
    
    def __init__(
        self,
        block_size: int = DEFAULT_BLOCK_SIZE,
        max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
        shadow_storage_path: Optional[str] = None,
        compression_level: int = COMPRESSION_LEVEL,
    ):
        """
        Initialize the SnapshotManager.
        
        Args:
            block_size: Size of each block for snapshotting
            max_memory_bytes: Maximum memory to use for in-memory snapshots
            shadow_storage_path: Optional directory for persistent shadow storage
            compression_level: zlib compression level (1-9)
        """
        self.block_size = block_size
        self.max_memory_bytes = max_memory_bytes
        self.shadow_storage_path = shadow_storage_path
        self.compression_level = compression_level
        
        # In-memory snapshot storage: {inode: FileSnapshot}
        self._snapshots: Dict[int, FileSnapshot] = {}
        
        # Track access times for LRU eviction: {inode: last_access_time}
        self._access_times: Dict[int, float] = {}
        
        # Current memory usage tracking
        self._current_memory_usage = 0
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
        # Create shadow storage directory if specified
        if shadow_storage_path:
            Path(shadow_storage_path).mkdir(parents=True, exist_ok=True)
    
    def _calculate_block_offset(self, file_offset: int) -> int:
        """Calculate the block-aligned offset for a given file offset."""
        return (file_offset // self.block_size) * self.block_size
    
    def _compress_block(self, data: bytes) -> Tuple[bytes, str]:
        """
        Compress a data block and compute checksum.
        
        Returns:
            Tuple of (compressed_data, checksum)
        """
        checksum = hashlib.sha256(data).hexdigest()
        compressed = zlib.compress(data, level=self.compression_level)
        return compressed, checksum
    
    def _evict_lru_snapshots(self, required_space: int) -> None:
        """
        Evict least-recently-used snapshots to free memory.
        
        Args:
            required_space: Bytes of space needed
        """
        # Sort by access time (oldest first)
        sorted_inodes = sorted(
            self._access_times.keys(),
            key=lambda i: self._access_times.get(i, 0)
        )
        
        freed = 0
        for inode in sorted_inodes:
            if freed >= required_space:
                break
            if inode in self._snapshots:
                snapshot = self._snapshots[inode]
                freed += snapshot.total_compressed_size
                self._current_memory_usage -= snapshot.total_compressed_size
                
                # Optionally persist to shadow storage before eviction
                if self.shadow_storage_path:
                    self._persist_snapshot(inode)
                
                del self._snapshots[inode]
                del self._access_times[inode]
    
    def _persist_snapshot(self, inode: int) -> None:
        """Persist a snapshot to shadow storage directory."""
        if not self.shadow_storage_path or inode not in self._snapshots:
            return
        
        snapshot = self._snapshots[inode]
        snapshot_dir = Path(self.shadow_storage_path) / f"inode_{inode}"
        snapshot_dir.mkdir(exist_ok=True)
        
        # Save metadata
        metadata_path = snapshot_dir / "metadata.txt"
        with open(metadata_path, 'w') as f:
            f.write(f"inode={snapshot.inode}\n")
            f.write(f"path={snapshot.path}\n")
            f.write(f"original_size={snapshot.original_size}\n")
            f.write(f"created_at={snapshot.created_at}\n")
            f.write(f"block_count={snapshot.block_count}\n")
        
        # Save each block
        for offset, block in snapshot.blocks.items():
            block_path = snapshot_dir / f"block_{offset}.zlib"
            with open(block_path, 'wb') as f:
                f.write(block.compressed_data)
            
            # Save block metadata
            block_meta_path = snapshot_dir / f"block_{offset}.meta"
            with open(block_meta_path, 'w') as f:
                f.write(f"offset={block.offset}\n")
                f.write(f"original_size={block.original_size}\n")
                f.write(f"checksum={block.checksum}\n")
                f.write(f"timestamp={block.timestamp}\n")
    
    def _load_snapshot_from_shadow(self, inode: int) -> Optional[FileSnapshot]:
        """Load a snapshot from shadow storage if available."""
        if not self.shadow_storage_path:
            return None
        
        snapshot_dir = Path(self.shadow_storage_path) / f"inode_{inode}"
        if not snapshot_dir.exists():
            return None
        
        try:
            # Load metadata
            metadata_path = snapshot_dir / "metadata.txt"
            metadata = {}
            with open(metadata_path, 'r') as f:
                for line in f:
                    key, value = line.strip().split('=', 1)
                    metadata[key] = value
            
            snapshot = FileSnapshot(
                inode=int(metadata['inode']),
                path=metadata['path'],
                original_size=int(metadata['original_size']),
                created_at=float(metadata['created_at']),
            )
            
            # Load blocks
            for block_file in snapshot_dir.glob("block_*.zlib"):
                offset = int(block_file.stem.split('_')[1])
                
                # Load compressed data
                with open(block_file, 'rb') as f:
                    compressed_data = f.read()
                
                # Load block metadata
                block_meta_path = snapshot_dir / f"block_{offset}.meta"
                block_meta = {}
                with open(block_meta_path, 'r') as f:
                    for line in f:
                        key, value = line.strip().split('=', 1)
                        block_meta[key] = value
                
                block = CompressedBlock(
                    compressed_data=compressed_data,
                    original_size=int(block_meta['original_size']),
                    offset=int(block_meta['offset']),
                    timestamp=float(block_meta['timestamp']),
                    checksum=block_meta['checksum'],
                )
                snapshot.blocks[offset] = block
            
            return snapshot
        except Exception:
            return None
    
    def save_block(
        self,
        inode: int,
        path: str,
        offset: int,
        original_data: bytes,
        file_size: int = 0,
    ) -> bool:
        """
        Save original data block before a write operation (Copy-on-Write).
        
        This is the core CoW mechanism: before any write is committed,
        we save the original data so it can be restored if the write
        turns out to be malicious.
        
        Args:
            inode: File inode number
            path: File path (for reconstruction)
            offset: Offset within file where write will occur
            original_data: Original data at this location (BEFORE the write)
            file_size: Current file size
            
        Returns:
            True if block was saved successfully
        """
        if not original_data:
            return False
        
        # Calculate block-aligned offset
        block_offset = self._calculate_block_offset(offset)
        
        # Compress the block
        compressed_data, checksum = self._compress_block(original_data)
        compressed_size = len(compressed_data)
        
        with self._lock:
            # Check if we need to evict old snapshots
            if self._current_memory_usage + compressed_size > self.max_memory_bytes:
                self._evict_lru_snapshots(compressed_size)
            
            # Get or create file snapshot
            if inode not in self._snapshots:
                self._snapshots[inode] = FileSnapshot(
                    inode=inode,
                    path=path,
                    original_size=file_size,
                )
            
            snapshot = self._snapshots[inode]
            
            # Check if we already have this block
            # Only save if we don't have it (first write wins for recovery)
            if block_offset not in snapshot.blocks:
                block = CompressedBlock(
                    compressed_data=compressed_data,
                    original_size=len(original_data),
                    offset=block_offset,
                    timestamp=time.time(),
                    checksum=checksum,
                )
                
                snapshot.blocks[block_offset] = block
                snapshot.last_modified = time.time()
                self._current_memory_usage += compressed_size
            
            # Update access time
            self._access_times[inode] = time.time()
        
        return True
    
    def save_blocks_for_write(
        self,
        inode: int,
        path: str,
        write_offset: int,
        write_size: int,
        read_original_func,
        file_size: int = 0,
    ) -> int:
        """
        Save all blocks affected by a write operation.
        
        This method calculates which blocks will be affected by a write
        and saves each one before the write proceeds.
        
        Args:
            inode: File inode
            path: File path
            write_offset: Starting offset of the write
            write_size: Size of data being written
            read_original_func: Callable(offset, size) -> bytes to read original data
            file_size: Current file size
            
        Returns:
            Number of blocks saved
        """
        if write_size <= 0:
            return 0
        
        # Calculate affected block range
        start_block = self._calculate_block_offset(write_offset)
        end_offset = write_offset + write_size
        end_block = self._calculate_block_offset(end_offset - 1) + self.block_size
        
        blocks_saved = 0
        
        # Save each affected block
        current_offset = start_block
        while current_offset < end_block and current_offset < file_size:
            # Read the original data for this block
            read_size = min(self.block_size, file_size - current_offset)
            if read_size > 0:
                try:
                    original_data = read_original_func(current_offset, read_size)
                    if original_data:
                        if self.save_block(inode, path, current_offset, original_data, file_size):
                            blocks_saved += 1
                except Exception:
                    pass  # Best effort - continue with other blocks
            
            current_offset += self.block_size
        
        return blocks_saved
    
    def get_snapshot(self, inode: int) -> Optional[FileSnapshot]:
        """
        Get snapshot for a file.
        
        Args:
            inode: File inode
            
        Returns:
            FileSnapshot if available, None otherwise
        """
        with self._lock:
            if inode in self._snapshots:
                self._access_times[inode] = time.time()
                return self._snapshots[inode]
        
        # Try loading from shadow storage
        return self._load_snapshot_from_shadow(inode)
    
    def restore_file(
        self,
        path: str,
        inode: Optional[int] = None,
        target_path: Optional[str] = None,
    ) -> bool:
        """
        Restore a file from its micro-snapshots.
        
        Reconstructs the original file content from saved block snapshots.
        
        Args:
            path: Original file path (used to find snapshot if inode not given)
            inode: File inode (if known)
            target_path: Where to write restored file (defaults to original path)
            
        Returns:
            True if restoration was successful
        """
        # Find snapshot
        snapshot = None
        
        if inode is not None:
            snapshot = self.get_snapshot(inode)
        
        # Search by path if inode not found
        if snapshot is None:
            with self._lock:
                for snap in self._snapshots.values():
                    if snap.path == path:
                        snapshot = snap
                        break
        
        if snapshot is None:
            return False
        
        if not snapshot.blocks:
            return False
        
        # Determine output path
        output_path = target_path or path
        
        try:
            # Sort blocks by offset
            sorted_offsets = sorted(snapshot.blocks.keys())
            
            # Reconstruct file
            with open(output_path, 'wb') as f:
                current_pos = 0
                for offset in sorted_offsets:
                    block = snapshot.blocks[offset]
                    
                    # Handle gaps (shouldn't happen normally, but be safe)
                    if offset > current_pos:
                        f.write(b'\x00' * (offset - current_pos))
                    
                    # Write decompressed block
                    original_data = block.decompress()
                    f.seek(offset)
                    f.write(original_data)
                    current_pos = offset + len(original_data)
                
                # Truncate to original size if known
                if snapshot.original_size > 0:
                    f.truncate(snapshot.original_size)
            
            return True
            
        except Exception:
            return False
    
    def restore_file_to_bytes(self, inode: int) -> Optional[bytes]:
        """
        Restore a file to a bytes buffer instead of writing to disk.
        
        Useful for serving restored content without modifying the filesystem.
        
        Args:
            inode: File inode
            
        Returns:
            Reconstructed file content as bytes, or None if not available
        """
        snapshot = self.get_snapshot(inode)
        if snapshot is None or not snapshot.blocks:
            return None
        
        try:
            # Reconstruct in memory
            result = bytearray()
            sorted_offsets = sorted(snapshot.blocks.keys())
            
            for offset in sorted_offsets:
                block = snapshot.blocks[offset]
                
                # Extend result to accommodate this block
                while len(result) < offset:
                    result.append(0)
                
                # Decompress and insert
                original_data = block.decompress()
                
                # Overwrite or extend
                end_offset = offset + len(original_data)
                if end_offset > len(result):
                    result.extend(b'\x00' * (end_offset - len(result)))
                
                result[offset:end_offset] = original_data
            
            # Truncate to original size
            if snapshot.original_size > 0 and len(result) > snapshot.original_size:
                result = result[:snapshot.original_size]
            
            return bytes(result)
            
        except Exception:
            return None
    
    def has_snapshot(self, inode: int) -> bool:
        """Check if a snapshot exists for the given inode."""
        with self._lock:
            return inode in self._snapshots
    
    def delete_snapshot(self, inode: int) -> bool:
        """
        Delete snapshot for a file.
        
        Should be called when we're confident the file is safe
        (e.g., after successful scan or user confirmation).
        
        Args:
            inode: File inode
            
        Returns:
            True if snapshot was deleted
        """
        with self._lock:
            if inode in self._snapshots:
                snapshot = self._snapshots[inode]
                self._current_memory_usage -= snapshot.total_compressed_size
                del self._snapshots[inode]
                self._access_times.pop(inode, None)
                
                # Also delete from shadow storage
                if self.shadow_storage_path:
                    snapshot_dir = Path(self.shadow_storage_path) / f"inode_{inode}"
                    if snapshot_dir.exists():
                        import shutil
                        shutil.rmtree(snapshot_dir, ignore_errors=True)
                
                return True
        return False
    
    def clear_all_snapshots(self) -> None:
        """Clear all snapshots from memory and shadow storage."""
        with self._lock:
            self._snapshots.clear()
            self._access_times.clear()
            self._current_memory_usage = 0
        
        # Clear shadow storage
        if self.shadow_storage_path:
            shadow_path = Path(self.shadow_storage_path)
            if shadow_path.exists():
                import shutil
                for item in shadow_path.iterdir():
                    if item.is_dir() and item.name.startswith("inode_"):
                        shutil.rmtree(item, ignore_errors=True)
    
    def get_stats(self) -> dict:
        """Get snapshot manager statistics."""
        with self._lock:
            total_blocks = sum(s.block_count for s in self._snapshots.values())
            total_original = sum(s.total_original_size for s in self._snapshots.values())
            
            return {
                'snapshot_count': len(self._snapshots),
                'total_blocks': total_blocks,
                'memory_usage_bytes': self._current_memory_usage,
                'memory_limit_bytes': self.max_memory_bytes,
                'memory_usage_percent': (self._current_memory_usage / self.max_memory_bytes * 100) if self.max_memory_bytes > 0 else 0,
                'total_original_size': total_original,
                'compression_ratio': (self._current_memory_usage / total_original) if total_original > 0 else 0,
                'block_size': self.block_size,
                'shadow_storage_enabled': self.shadow_storage_path is not None,
            }
    
    def list_snapshots(self) -> List[dict]:
        """List all available snapshots."""
        with self._lock:
            return [
                {
                    'inode': s.inode,
                    'path': s.path,
                    'block_count': s.block_count,
                    'original_size': s.original_size,
                    'compressed_size': s.total_compressed_size,
                    'created_at': s.created_at,
                    'last_modified': s.last_modified,
                }
                for s in self._snapshots.values()
            ]
