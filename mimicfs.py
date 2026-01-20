"""
MimicFS - A FUSE-based ransomware-defensive filesystem.

This module implements the core filesystem class that:
1. Intercepts all filesystem operations (write, rename, unlink, chmod)
2. Analyzes operations for ransomware behavior using ThreatAnalyzer
3. Creates micro-snapshots using Copy-on-Write via SnapshotManager
4. Responds adaptively: block, misdirect to honeypot, or allow
5. Logs all suspicious activity via ForensicLogger

Architecture based on pyfuse3's passthrough filesystem example,
extended with defensive capabilities.
"""

import os
import stat
import errno
import time
from pathlib import Path
from collections import defaultdict
from typing import Optional, Dict, Set, Tuple
import threading

import pyfuse3
from pyfuse3 import FUSEError

from threat_analyzer import ThreatAnalyzer, OperationContext, ThreatType
from snapshot_manager import SnapshotManager
from forensic_logger import ForensicLogger, EventType, LogLevel


# Type aliases for clarity
InodeT = int
FileHandleT = int


class ResponseAction:
    """Possible responses to a threat."""
    ALLOW = "allow"
    BLOCK = "block"
    MISDIRECT = "misdirect"


class MimicFSConfig:
    """Configuration for MimicFS behavior."""
    
    def __init__(
        self,
        # Threat thresholds
        block_threshold: float = 0.8,      # Confidence above which to block
        misdirect_threshold: float = 0.5,   # Confidence above which to misdirect
        entropy_threshold: float = 7.0,     # Entropy level for suspicious writes
        
        # Snapshot settings
        snapshot_max_memory_mb: int = 512,
        shadow_storage_path: Optional[str] = None,
        block_size: int = 4096,
        
        # Honeypot settings
        honeypot_dir: str = ".mimicfs_honeypot",
        
        # Logging
        log_file: Optional[str] = None,
        console_logging: bool = True,
        
        # Behavior flags
        enable_snapshots: bool = True,
        enable_honeypot: bool = True,
        read_only_mode: bool = False,
    ):
        self.block_threshold = block_threshold
        self.misdirect_threshold = misdirect_threshold
        self.entropy_threshold = entropy_threshold
        self.snapshot_max_memory_mb = snapshot_max_memory_mb
        self.shadow_storage_path = shadow_storage_path
        self.block_size = block_size
        self.honeypot_dir = honeypot_dir
        self.log_file = log_file
        self.console_logging = console_logging
        self.enable_snapshots = enable_snapshots
        self.enable_honeypot = enable_honeypot
        self.read_only_mode = read_only_mode


class MimicFS(pyfuse3.Operations):
    """
    MimicFS - Ransomware-defensive FUSE filesystem.
    
    This filesystem acts as a passthrough layer over an existing directory,
    intercepting all operations and analyzing them for ransomware-like behavior.
    
    Key Features:
    - Transparent passthrough for normal operations
    - Entropy analysis on write data to detect encryption
    - Modification frequency tracking
    - Extension change detection
    - Block-level Copy-on-Write snapshots
    - Honeypot misdirection for suspicious writes
    - Comprehensive forensic logging
    
    Usage:
        fs = MimicFS(source_dir="/path/to/protect")
        pyfuse3.init(fs, mountpoint, options)
        trio.run(pyfuse3.main)
    """
    
    # Inode for the root directory
    ROOT_INODE = pyfuse3.ROOT_INODE
    
    def __init__(
        self,
        source_dir: str,
        config: Optional[MimicFSConfig] = None,
    ):
        """
        Initialize MimicFS.
        
        Args:
            source_dir: The directory to protect (passthrough target)
            config: Configuration options
        """
        super().__init__()
        
        self.source_dir = os.path.abspath(source_dir)
        self.config = config or MimicFSConfig()
        
        # Verify source directory exists
        if not os.path.isdir(self.source_dir):
            raise ValueError(f"Source directory does not exist: {self.source_dir}")
        
        # ==================== INODE MANAGEMENT ====================
        # Map inode -> path (or set of paths for hardlinks)
        self._inode_path_map: Dict[InodeT, str | Set[str]] = {
            self.ROOT_INODE: self.source_dir
        }
        
        # Map path -> inode (for reverse lookups)
        self._path_inode_map: Dict[str, InodeT] = {
            self.source_dir: self.ROOT_INODE
        }
        
        # Track lookup counts for proper inode management
        self._lookup_cnt: Dict[InodeT, int] = defaultdict(int)
        self._lookup_cnt[self.ROOT_INODE] = 1
        
        # Next available inode number
        self._next_inode = self.ROOT_INODE + 1
        
        # ==================== FILE HANDLE MANAGEMENT ====================
        # Map file handle -> (inode, os_fd)
        self._fh_map: Dict[FileHandleT, Tuple[InodeT, int]] = {}
        
        # Map inode -> list of file handles
        self._inode_fh_map: Dict[InodeT, Set[FileHandleT]] = defaultdict(set)
        
        # Next available file handle
        self._next_fh = 1
        
        # ==================== DIRECTORY HANDLE MANAGEMENT ====================
        # Map dir handle -> (inode, iterator position)
        self._dh_map: Dict[FileHandleT, Tuple[InodeT, list]] = {}
        self._next_dh = 1
        
        # ==================== DEFENSIVE COMPONENTS ====================
        # Threat analyzer for heuristic detection
        self.threat_analyzer = ThreatAnalyzer(
            entropy_threshold=self.config.entropy_threshold,
        )
        
        # Snapshot manager for Copy-on-Write
        if self.config.enable_snapshots:
            self.snapshot_manager = SnapshotManager(
                block_size=self.config.block_size,
                max_memory_bytes=self.config.snapshot_max_memory_mb * 1024 * 1024,
                shadow_storage_path=self.config.shadow_storage_path,
            )
        else:
            self.snapshot_manager = None
        
        # Forensic logger
        self.logger = ForensicLogger(
            log_file=self.config.log_file,
            console_output=self.config.console_logging,
        )
        
        # ==================== HONEYPOT MANAGEMENT ====================
        # Honeypot directory (within source, hidden)
        self._honeypot_path = os.path.join(self.source_dir, self.config.honeypot_dir)
        if self.config.enable_honeypot:
            os.makedirs(self._honeypot_path, exist_ok=True)
        
        # Track which file handles are honeypot redirects
        # Map: original_inode -> honeypot_fd
        self._honeypot_fds: Dict[InodeT, int] = {}
        
        # ==================== THREAD SAFETY ====================
        self._lock = threading.Lock()
        
        # Log startup
        self.logger.log_system_event(
            EventType.FILESYSTEM_MOUNTED,
            f"MimicFS mounted: {source_dir}",
            {"source_dir": source_dir, "config": vars(self.config)},
        )
    
    # ==================== PATH/INODE HELPERS ====================
    
    def _get_path(self, inode: InodeT) -> str:
        """Get path for an inode."""
        path = self._inode_path_map.get(inode)
        if path is None:
            raise FUSEError(errno.ENOENT)
        if isinstance(path, set):
            # Return any path for hardlinked files
            return next(iter(path))
        return path
    
    def _add_path(self, inode: InodeT, path: str) -> None:
        """Add a path mapping for an inode."""
        with self._lock:
            self._path_inode_map[path] = inode
            
            if inode not in self._inode_path_map:
                self._inode_path_map[inode] = path
            elif isinstance(self._inode_path_map[inode], set):
                self._inode_path_map[inode].add(path)
            else:
                # Convert to set for hardlinks
                existing = self._inode_path_map[inode]
                self._inode_path_map[inode] = {existing, path}
    
    def _remove_path(self, path: str) -> Optional[InodeT]:
        """Remove a path mapping. Returns inode if mapping existed."""
        with self._lock:
            inode = self._path_inode_map.pop(path, None)
            if inode is None:
                return None
            
            paths = self._inode_path_map.get(inode)
            if isinstance(paths, set):
                paths.discard(path)
                if len(paths) == 1:
                    self._inode_path_map[inode] = next(iter(paths))
                elif len(paths) == 0:
                    del self._inode_path_map[inode]
            elif paths == path:
                del self._inode_path_map[inode]
            
            return inode
    
    def _get_or_create_inode(self, path: str) -> InodeT:
        """Get existing inode for path or create a new one."""
        with self._lock:
            if path in self._path_inode_map:
                return self._path_inode_map[path]
            
            # Get real inode from filesystem for consistency
            try:
                st = os.lstat(path)
                # Use real inode if not already mapped differently
                real_inode = st.st_ino
                
                # Check if this real inode is already known
                # (handles hardlinks)
                for known_inode, known_path in self._inode_path_map.items():
                    if isinstance(known_path, str) and os.path.exists(known_path):
                        try:
                            if os.lstat(known_path).st_ino == real_inode:
                                self._path_inode_map[path] = known_inode
                                if isinstance(self._inode_path_map[known_inode], set):
                                    self._inode_path_map[known_inode].add(path)
                                else:
                                    self._inode_path_map[known_inode] = {
                                        self._inode_path_map[known_inode], path
                                    }
                                return known_inode
                        except OSError:
                            pass
            except OSError:
                pass
            
            # Assign new FUSE inode
            inode = self._next_inode
            self._next_inode += 1
            
            self._inode_path_map[inode] = path
            self._path_inode_map[path] = inode
            
            return inode
    
    # ==================== THREAT ANALYSIS & RESPONSE ====================
    
    def _analyze_and_respond(
        self,
        operation: str,
        inode: InodeT,
        ctx: pyfuse3.RequestContext,
        data: Optional[bytes] = None,
        old_name: Optional[str] = None,
        new_name: Optional[str] = None,
    ) -> Tuple[str, float]:
        """
        Analyze an operation and determine the response.
        
        This is the core decision-making function that:
        1. Creates operation context
        2. Runs threat analysis
        3. Logs if suspicious
        4. Returns the appropriate response action
        
        Args:
            operation: Operation type ('write', 'rename', 'unlink', 'chmod')
            inode: File inode
            ctx: FUSE request context (contains pid, uid, gid)
            data: Data buffer for write operations
            old_name: Original filename for rename operations
            new_name: New filename for rename operations
            
        Returns:
            Tuple of (ResponseAction, confidence)
        """
        path = self._get_path(inode)
        
        # Create operation context for analysis
        op_ctx = OperationContext(
            operation=operation,
            inode=inode,
            path=path,
            data=data,
            old_name=old_name,
            new_name=new_name,
            pid=ctx.pid,
            timestamp=time.time(),
        )
        
        # Run threat analysis
        threat = self.threat_analyzer.analyze(op_ctx)
        confidence = threat.confidence
        
        # Log if suspicious
        if confidence >= self.config.misdirect_threshold:
            self.logger.log_threat(
                threat_type=threat.threat_type.value,
                confidence=confidence,
                operation=operation,
                path=path,
                inode=inode,
                pid=ctx.pid,
                uid=ctx.uid,
                entropy=threat.details.get('entropy'),
                details=threat.details,
            )
        
        # Determine response
        if confidence >= self.config.block_threshold:
            return ResponseAction.BLOCK, confidence
        elif confidence >= self.config.misdirect_threshold and self.config.enable_honeypot:
            return ResponseAction.MISDIRECT, confidence
        else:
            return ResponseAction.ALLOW, confidence
    
    def _get_honeypot_path(self, inode: InodeT) -> str:
        """Generate a honeypot file path for an inode."""
        return os.path.join(self._honeypot_path, f"honeypot_{inode}")
    
    # ==================== FUSE OPERATIONS: LOOKUP & ATTRIBUTES ====================
    
    async def lookup(
        self,
        parent_inode: InodeT,
        name: bytes,
        ctx: pyfuse3.RequestContext,
    ) -> pyfuse3.EntryAttributes:
        """Look up a directory entry by name."""
        parent_path = self._get_path(parent_inode)
        name_str = os.fsdecode(name)
        
        # Hide honeypot directory from listings
        if name_str == self.config.honeypot_dir:
            raise FUSEError(errno.ENOENT)
        
        path = os.path.join(parent_path, name_str)
        
        try:
            st = os.lstat(path)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        inode = self._get_or_create_inode(path)
        self._lookup_cnt[inode] += 1
        
        return self._make_entry_attributes(st, inode)
    
    async def getattr(
        self,
        inode: InodeT,
        ctx: pyfuse3.RequestContext,
    ) -> pyfuse3.EntryAttributes:
        """Get file attributes by inode."""
        path = self._get_path(inode)
        
        try:
            st = os.lstat(path)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        return self._make_entry_attributes(st, inode)
    
    async def setattr(
        self,
        inode: InodeT,
        attr: pyfuse3.EntryAttributes,
        fields: pyfuse3.SetattrFields,
        fh: Optional[FileHandleT],
        ctx: pyfuse3.RequestContext,
    ) -> pyfuse3.EntryAttributes:
        """
        Set file attributes (chmod, chown, truncate, utimens).
        
        CHMOD INTERCEPTION: When fields.update_mode is True, this is a chmod operation.
        We analyze it for suspicious patterns.
        """
        path = self._get_path(inode)
        
        # CHMOD INTERCEPTION
        if fields.update_mode:
            action, confidence = self._analyze_and_respond(
                operation='chmod',
                inode=inode,
                ctx=ctx,
            )
            
            if action == ResponseAction.BLOCK:
                self.logger.log_blocked_operation(
                    operation='chmod',
                    path=path,
                    inode=inode,
                    pid=ctx.pid,
                    uid=ctx.uid,
                    reason="High threat confidence",
                    threat_confidence=confidence,
                )
                raise FUSEError(errno.EACCES)
        
        try:
            # Apply attribute changes
            if fields.update_size:
                if fh is not None and fh in self._fh_map:
                    _, os_fd = self._fh_map[fh]
                    os.ftruncate(os_fd, attr.st_size)
                else:
                    os.truncate(path, attr.st_size)
            
            if fields.update_mode:
                os.chmod(path, stat.S_IMODE(attr.st_mode))
            
            if fields.update_uid or fields.update_gid:
                uid = attr.st_uid if fields.update_uid else -1
                gid = attr.st_gid if fields.update_gid else -1
                os.chown(path, uid, gid)
            
            if fields.update_atime or fields.update_mtime:
                atime = attr.st_atime_ns if fields.update_atime else None
                mtime = attr.st_mtime_ns if fields.update_mtime else None
                
                if fh is not None and fh in self._fh_map:
                    _, os_fd = self._fh_map[fh]
                    os.utime(os_fd, ns=(atime or 0, mtime or 0))
                else:
                    os.utime(path, ns=(atime or 0, mtime or 0))
            
            st = os.lstat(path)
            return self._make_entry_attributes(st, inode)
            
        except OSError as e:
            raise FUSEError(e.errno) from None
    
    def _make_entry_attributes(
        self,
        st: os.stat_result,
        inode: InodeT,
    ) -> pyfuse3.EntryAttributes:
        """Create EntryAttributes from stat result."""
        entry = pyfuse3.EntryAttributes()
        entry.st_ino = inode
        entry.st_mode = st.st_mode
        entry.st_nlink = st.st_nlink
        entry.st_uid = st.st_uid
        entry.st_gid = st.st_gid
        entry.st_rdev = st.st_rdev
        entry.st_size = st.st_size
        entry.st_blksize = st.st_blksize
        entry.st_blocks = st.st_blocks
        entry.st_atime_ns = st.st_atime_ns
        entry.st_mtime_ns = st.st_mtime_ns
        entry.st_ctime_ns = st.st_ctime_ns
        entry.generation = 0
        entry.entry_timeout = 5
        entry.attr_timeout = 5
        return entry
    
    # ==================== FUSE OPERATIONS: FILE I/O ====================
    
    async def open(
        self,
        inode: InodeT,
        flags: int,
        ctx: pyfuse3.RequestContext,
    ) -> pyfuse3.FileInfo:
        """Open a file."""
        path = self._get_path(inode)
        
        try:
            fd = os.open(path, flags)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        # Allocate file handle
        with self._lock:
            fh = self._next_fh
            self._next_fh += 1
            self._fh_map[fh] = (inode, fd)
            self._inode_fh_map[inode].add(fh)
        
        return pyfuse3.FileInfo(fh=fh)
    
    async def create(
        self,
        parent_inode: InodeT,
        name: bytes,
        mode: int,
        flags: int,
        ctx: pyfuse3.RequestContext,
    ) -> Tuple[pyfuse3.FileInfo, pyfuse3.EntryAttributes]:
        """Create and open a file."""
        parent_path = self._get_path(parent_inode)
        name_str = os.fsdecode(name)
        path = os.path.join(parent_path, name_str)
        
        try:
            fd = os.open(path, flags | os.O_CREAT, mode)
            st = os.fstat(fd)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        inode = self._get_or_create_inode(path)
        self._lookup_cnt[inode] += 1
        
        # Allocate file handle
        with self._lock:
            fh = self._next_fh
            self._next_fh += 1
            self._fh_map[fh] = (inode, fd)
            self._inode_fh_map[inode].add(fh)
        
        entry = self._make_entry_attributes(st, inode)
        return pyfuse3.FileInfo(fh=fh), entry
    
    async def read(
        self,
        fh: FileHandleT,
        offset: int,
        size: int,
    ) -> bytes:
        """Read data from an open file."""
        if fh not in self._fh_map:
            raise FUSEError(errno.EBADF)
        
        _, fd = self._fh_map[fh]
        
        try:
            os.lseek(fd, offset, os.SEEK_SET)
            return os.read(fd, size)
        except OSError as e:
            raise FUSEError(e.errno) from None
    
    async def write(
        self,
        fh: FileHandleT,
        offset: int,
        buf: bytes,
        ctx: pyfuse3.RequestContext,
    ) -> int:
        """
        Write data to an open file.
        
        ============================================================
        WRITE INTERCEPTION - CORE RANSOMWARE DEFENSE LOGIC
        ============================================================
        
        This method implements the full defensive pipeline:
        
        1. ENTROPY CHECK: Calculate Shannon entropy of the write buffer.
           High entropy (>7.0 bits/byte) indicates encrypted data.
        
        2. THREAT ANALYSIS: Combine entropy with other heuristics
           (modification frequency, extension patterns) to get confidence score.
        
        3. SNAPSHOT CREATION (Copy-on-Write): Before any write is committed,
           save the original data blocks that will be overwritten.
           This enables recovery if the write is later determined malicious.
        
        4. ADAPTIVE RESPONSE:
           - BLOCK: If confidence >= 0.8, deny the write entirely
           - MISDIRECT: If confidence >= 0.5, redirect to honeypot file
           - ALLOW: If confidence < 0.5, proceed with snapshotted write
        """
        if fh not in self._fh_map:
            raise FUSEError(errno.EBADF)
        
        inode, fd = self._fh_map[fh]
        path = self._get_path(inode)
        
        # Check if this is already a honeypot redirect
        if inode in self._honeypot_fds:
            # Write to honeypot instead
            honeypot_fd = self._honeypot_fds[inode]
            try:
                os.lseek(honeypot_fd, offset, os.SEEK_SET)
                return os.write(honeypot_fd, buf)
            except OSError as e:
                raise FUSEError(e.errno) from None
        
        # ============================================================
        # STEP 1 & 2: ENTROPY CHECK + THREAT ANALYSIS
        # ============================================================
        # The analyze_and_respond method calls ThreatAnalyzer.analyze()
        # which internally calls calculate_entropy() on the write buffer
        # to detect high-entropy (potentially encrypted) data.
        
        action, confidence = self._analyze_and_respond(
            operation='write',
            inode=inode,
            ctx=ctx,
            data=buf,  # <- This buffer is analyzed for entropy
        )
        
        # ============================================================
        # STEP 4: ADAPTIVE RESPONSE - BLOCK
        # ============================================================
        if action == ResponseAction.BLOCK:
            self.logger.log_blocked_operation(
                operation='write',
                path=path,
                inode=inode,
                pid=ctx.pid,
                uid=ctx.uid,
                reason="High entropy write detected - possible ransomware encryption",
                threat_confidence=confidence,
            )
            # Return EACCES to deny the write
            raise FUSEError(errno.EACCES)
        
        # ============================================================
        # STEP 4: ADAPTIVE RESPONSE - MISDIRECT TO HONEYPOT
        # ============================================================
        if action == ResponseAction.MISDIRECT:
            # Create honeypot file and redirect writes there
            honeypot_path = self._get_honeypot_path(inode)
            
            try:
                # Copy current file to honeypot if it doesn't exist
                if not os.path.exists(honeypot_path):
                    # Read entire original file
                    os.lseek(fd, 0, os.SEEK_SET)
                    original_content = b''
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        original_content += chunk
                    
                    # Write to honeypot
                    with open(honeypot_path, 'wb') as hf:
                        hf.write(original_content)
                
                # Open honeypot for writing
                honeypot_fd = os.open(honeypot_path, os.O_RDWR)
                self._honeypot_fds[inode] = honeypot_fd
                
                # Log the misdirection
                self.logger.log_misdirection(
                    operation='write',
                    original_path=path,
                    honeypot_path=honeypot_path,
                    inode=inode,
                    pid=ctx.pid,
                    uid=ctx.uid,
                )
                
                # Write to honeypot instead of real file
                os.lseek(honeypot_fd, offset, os.SEEK_SET)
                return os.write(honeypot_fd, buf)
                
            except OSError as e:
                self.logger.log_error(
                    f"Failed to create honeypot: {e}",
                    exception=e,
                )
                # Fall through to normal write if honeypot fails
        
        # ============================================================
        # STEP 3: SNAPSHOT CREATION (Copy-on-Write)
        # ============================================================
        # Before allowing the write, save original data for recovery
        if self.snapshot_manager:
            try:
                # Get current file size
                st = os.fstat(fd)
                file_size = st.st_size
                
                # Only snapshot if we're overwriting existing data
                if offset < file_size:
                    # Read original data at the affected region
                    read_size = min(len(buf), file_size - offset)
                    if read_size > 0:
                        os.lseek(fd, offset, os.SEEK_SET)
                        original_data = os.read(fd, read_size)
                        
                        # Save to snapshot manager
                        # This implements block-level CoW
                        self.snapshot_manager.save_block(
                            inode=inode,
                            path=path,
                            offset=offset,
                            original_data=original_data,
                            file_size=file_size,
                        )
            except OSError:
                pass  # Best effort - don't fail write if snapshot fails
        
        # ============================================================
        # STEP 4: ADAPTIVE RESPONSE - ALLOW (PROCEED WITH WRITE)
        # ============================================================
        try:
            os.lseek(fd, offset, os.SEEK_SET)
            return os.write(fd, buf)
        except OSError as e:
            raise FUSEError(e.errno) from None
    
    async def release(
        self,
        fh: FileHandleT,
    ) -> None:
        """Close an open file."""
        if fh not in self._fh_map:
            return
        
        inode, fd = self._fh_map[fh]
        
        with self._lock:
            del self._fh_map[fh]
            self._inode_fh_map[inode].discard(fh)
        
        try:
            os.close(fd)
        except OSError:
            pass
        
        # Close honeypot fd if any
        if inode in self._honeypot_fds:
            try:
                os.close(self._honeypot_fds[inode])
            except OSError:
                pass
            del self._honeypot_fds[inode]
    
    # ==================== FUSE OPERATIONS: RENAME ====================
    
    async def rename(
        self,
        parent_inode_old: InodeT,
        name_old: bytes,
        parent_inode_new: InodeT,
        name_new: bytes,
        flags: int,
        ctx: pyfuse3.RequestContext,
    ) -> None:
        """
        Rename a file or directory.
        
        RENAME INTERCEPTION: Monitors for suspicious extension changes
        (e.g., .txt -> .encrypted) which is a common ransomware pattern.
        """
        parent_path_old = self._get_path(parent_inode_old)
        parent_path_new = self._get_path(parent_inode_new)
        
        name_old_str = os.fsdecode(name_old)
        name_new_str = os.fsdecode(name_new)
        
        path_old = os.path.join(parent_path_old, name_old_str)
        path_new = os.path.join(parent_path_new, name_new_str)
        
        # Get inode of file being renamed
        inode = self._path_inode_map.get(path_old)
        if inode is None:
            try:
                inode = self._get_or_create_inode(path_old)
            except FUSEError:
                raise FUSEError(errno.ENOENT) from None
        
        # RENAME ANALYSIS: Check for suspicious extension changes
        action, confidence = self._analyze_and_respond(
            operation='rename',
            inode=inode,
            ctx=ctx,
            old_name=name_old_str,
            new_name=name_new_str,
        )
        
        if action == ResponseAction.BLOCK:
            self.logger.log_blocked_operation(
                operation='rename',
                path=path_old,
                inode=inode,
                pid=ctx.pid,
                uid=ctx.uid,
                reason=f"Suspicious rename: {name_old_str} -> {name_new_str}",
                threat_confidence=confidence,
            )
            raise FUSEError(errno.EACCES)
        
        # For misdirect on rename, we just log but allow (can't easily redirect)
        if action == ResponseAction.MISDIRECT:
            self.logger.log_threat(
                threat_type="suspicious_rename",
                confidence=confidence,
                operation='rename',
                path=path_old,
                inode=inode,
                pid=ctx.pid,
                uid=ctx.uid,
                details={
                    "old_name": name_old_str,
                    "new_name": name_new_str,
                    "note": "Allowed but flagged - monitor this process",
                },
            )
        
        try:
            os.rename(path_old, path_new)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        # Update path mappings
        self._remove_path(path_old)
        self._add_path(inode, path_new)
    
    # ==================== FUSE OPERATIONS: UNLINK (DELETE) ====================
    
    async def unlink(
        self,
        parent_inode: InodeT,
        name: bytes,
        ctx: pyfuse3.RequestContext,
    ) -> None:
        """
        Delete a file.
        
        UNLINK INTERCEPTION: Mass deletion is a ransomware indicator.
        We snapshot before deletion and can block if suspicious.
        """
        parent_path = self._get_path(parent_inode)
        name_str = os.fsdecode(name)
        path = os.path.join(parent_path, name_str)
        
        # Get inode
        inode = self._path_inode_map.get(path)
        if inode is None:
            try:
                inode = self._get_or_create_inode(path)
            except FUSEError:
                raise FUSEError(errno.ENOENT) from None
        
        # UNLINK ANALYSIS
        action, confidence = self._analyze_and_respond(
            operation='unlink',
            inode=inode,
            ctx=ctx,
        )
        
        if action == ResponseAction.BLOCK:
            self.logger.log_blocked_operation(
                operation='unlink',
                path=path,
                inode=inode,
                pid=ctx.pid,
                uid=ctx.uid,
                reason="Mass deletion pattern detected",
                threat_confidence=confidence,
            )
            raise FUSEError(errno.EACCES)
        
        # Snapshot entire file before deletion for recovery
        if self.snapshot_manager:
            try:
                with open(path, 'rb') as f:
                    content = f.read()
                    st = os.fstat(f.fileno())
                    
                # Save in chunks
                offset = 0
                while offset < len(content):
                    chunk = content[offset:offset + self.config.block_size]
                    self.snapshot_manager.save_block(
                        inode=inode,
                        path=path,
                        offset=offset,
                        original_data=chunk,
                        file_size=st.st_size,
                    )
                    offset += self.config.block_size
            except OSError:
                pass  # Best effort
        
        try:
            os.unlink(path)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        self._remove_path(path)
    
    # ==================== FUSE OPERATIONS: DIRECTORY ====================
    
    async def opendir(
        self,
        inode: InodeT,
        ctx: pyfuse3.RequestContext,
    ) -> FileHandleT:
        """Open a directory for reading."""
        path = self._get_path(inode)
        
        try:
            entries = os.listdir(path)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        # Filter out honeypot directory
        entries = [e for e in entries if e != self.config.honeypot_dir]
        
        with self._lock:
            dh = self._next_dh
            self._next_dh += 1
            self._dh_map[dh] = (inode, entries)
        
        return dh
    
    async def readdir(
        self,
        dh: FileHandleT,
        start_id: int,
        token: pyfuse3.ReaddirToken,
    ) -> None:
        """Read directory entries."""
        if dh not in self._dh_map:
            raise FUSEError(errno.EBADF)
        
        inode, entries = self._dh_map[dh]
        path = self._get_path(inode)
        
        for i, name in enumerate(entries[start_id:], start=start_id):
            entry_path = os.path.join(path, name)
            
            try:
                st = os.lstat(entry_path)
            except OSError:
                continue
            
            entry_inode = self._get_or_create_inode(entry_path)
            attr = self._make_entry_attributes(st, entry_inode)
            
            if not pyfuse3.readdir_reply(
                token,
                os.fsencode(name),
                attr,
                i + 1,
            ):
                break
    
    async def releasedir(
        self,
        dh: FileHandleT,
    ) -> None:
        """Close a directory handle."""
        with self._lock:
            self._dh_map.pop(dh, None)
    
    # ==================== FUSE OPERATIONS: MKDIR/RMDIR ====================
    
    async def mkdir(
        self,
        parent_inode: InodeT,
        name: bytes,
        mode: int,
        ctx: pyfuse3.RequestContext,
    ) -> pyfuse3.EntryAttributes:
        """Create a directory."""
        parent_path = self._get_path(parent_inode)
        name_str = os.fsdecode(name)
        path = os.path.join(parent_path, name_str)
        
        try:
            os.mkdir(path, mode)
            st = os.lstat(path)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        inode = self._get_or_create_inode(path)
        self._lookup_cnt[inode] += 1
        
        return self._make_entry_attributes(st, inode)
    
    async def rmdir(
        self,
        parent_inode: InodeT,
        name: bytes,
        ctx: pyfuse3.RequestContext,
    ) -> None:
        """Remove a directory."""
        parent_path = self._get_path(parent_inode)
        name_str = os.fsdecode(name)
        path = os.path.join(parent_path, name_str)
        
        try:
            os.rmdir(path)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        self._remove_path(path)
    
    # ==================== FUSE OPERATIONS: INODE MANAGEMENT ====================
    
    async def forget(
        self,
        inode_list: list,
    ) -> None:
        """Forget about inodes (kernel is done with them)."""
        for inode, nlookup in inode_list:
            with self._lock:
                if inode in self._lookup_cnt:
                    self._lookup_cnt[inode] -= nlookup
                    if self._lookup_cnt[inode] <= 0:
                        del self._lookup_cnt[inode]
                        # Don't delete path mapping - may still be needed
    
    async def statfs(
        self,
        ctx: pyfuse3.RequestContext,
    ) -> pyfuse3.StatvfsData:
        """Get filesystem statistics."""
        try:
            st = os.statvfs(self.source_dir)
        except OSError as e:
            raise FUSEError(e.errno) from None
        
        data = pyfuse3.StatvfsData()
        data.f_bsize = st.f_bsize
        data.f_frsize = st.f_frsize
        data.f_blocks = st.f_blocks
        data.f_bfree = st.f_bfree
        data.f_bavail = st.f_bavail
        data.f_files = st.f_files
        data.f_ffree = st.f_ffree
        data.f_favail = st.f_favail
        data.f_namemax = st.f_namemax
        return data
    
    # ==================== RECOVERY API ====================
    
    def restore_file(
        self,
        path: str,
        target_path: Optional[str] = None,
    ) -> bool:
        """
        Restore a file from micro-snapshots.
        
        This is the recovery function that reconstructs a file from
        its saved block snapshots after a ransomware attack.
        
        Args:
            path: Original file path (relative to mount point or absolute)
            target_path: Where to restore (defaults to original path)
            
        Returns:
            True if restoration succeeded
        """
        if not self.snapshot_manager:
            return False
        
        # Resolve path
        if not os.path.isabs(path):
            path = os.path.join(self.source_dir, path)
        
        return self.snapshot_manager.restore_file(path, target_path=target_path)
    
    def list_snapshots(self) -> list:
        """List all available file snapshots."""
        if not self.snapshot_manager:
            return []
        return self.snapshot_manager.list_snapshots()
    
    def get_stats(self) -> dict:
        """Get filesystem and defense statistics."""
        stats = {
            "source_dir": self.source_dir,
            "inodes_tracked": len(self._inode_path_map),
            "open_files": len(self._fh_map),
            "honeypot_redirects": len(self._honeypot_fds),
        }
        
        if self.snapshot_manager:
            stats["snapshots"] = self.snapshot_manager.get_stats()
        
        stats["threat_analyzer"] = self.threat_analyzer.get_stats()
        stats["recent_threats"] = self.logger.get_threat_summary(hours=1)
        
        return stats
