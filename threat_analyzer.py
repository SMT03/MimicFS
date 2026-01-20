"""
ThreatAnalyzer - Heuristic analysis engine for ransomware detection.

This module implements multiple detection strategies:
1. Shannon Entropy Analysis - detects encrypted/compressed data
2. Modification Frequency Tracking - detects rapid file changes
3. Extension Change Detection - detects mass extension changes
"""

import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import threading


class ThreatType(Enum):
    """Types of threats that can be detected."""
    NONE = "none"
    HIGH_ENTROPY_WRITE = "high_entropy_write"
    RAPID_MODIFICATION = "rapid_modification"
    MASS_EXTENSION_CHANGE = "mass_extension_change"
    MASS_DELETION = "mass_deletion"


@dataclass
class ThreatContext:
    """Context information about a detected threat."""
    threat_type: ThreatType
    confidence: float  # 0.0 to 1.0
    details: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class OperationContext:
    """Context for an operation being analyzed."""
    operation: str  # 'write', 'rename', 'unlink', 'chmod'
    inode: int
    path: Optional[str] = None
    data: Optional[bytes] = None  # For write operations
    old_name: Optional[str] = None  # For rename operations
    new_name: Optional[str] = None  # For rename operations
    pid: Optional[int] = None
    timestamp: float = field(default_factory=time.time)


class ThreatAnalyzer:
    """
    Analyzes filesystem operations for ransomware-like behavior.
    
    Detection Strategies:
    - Entropy Analysis: Encrypted data has high entropy (~7.5-8.0 bits/byte)
    - Frequency Analysis: Ransomware modifies many files rapidly
    - Extension Analysis: Ransomware often changes extensions to .encrypted, .locked, etc.
    """
    
    # Entropy thresholds (bits per byte, max is 8.0)
    HIGH_ENTROPY_THRESHOLD = 7.0  # Typical encrypted data
    SUSPICIOUS_ENTROPY_THRESHOLD = 6.5  # Compressed or partially encrypted
    
    # Frequency thresholds
    RAPID_MOD_WINDOW_SECONDS = 10.0  # Time window for frequency analysis
    RAPID_MOD_THRESHOLD = 10  # Number of operations to trigger alert
    
    # Extension change thresholds
    EXTENSION_CHANGE_WINDOW_SECONDS = 30.0
    EXTENSION_CHANGE_THRESHOLD = 5  # Mass extension changes to trigger alert
    
    # Known ransomware extensions
    SUSPICIOUS_EXTENSIONS = frozenset({
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
        '.locky', '.zepto', '.cerber', '.wallet', '.petya',
        '.wannacry', '.wncry', '.wncryt', '.wcry', '.ransm',
        '.crypted', '.cryptolocker', '.crinf', '.r5a', '.xrtn',
        '.xtbl', '.aaa', '.abc', '.xyz', '.bbb', '.ecc', '.ezz',
        '.exx', '.vvv', '.ttt', '.micro', '.kkk', '.fun',
        '.gws', '.btc', '.ctbl', '.ctb2', '.globe', '.breaking_bad',
    })
    
    def __init__(
        self,
        entropy_threshold: float = HIGH_ENTROPY_THRESHOLD,
        rapid_mod_threshold: int = RAPID_MOD_THRESHOLD,
        rapid_mod_window: float = RAPID_MOD_WINDOW_SECONDS,
        extension_change_threshold: int = EXTENSION_CHANGE_THRESHOLD,
    ):
        """
        Initialize the ThreatAnalyzer.
        
        Args:
            entropy_threshold: Entropy level (0-8) above which data is considered suspicious
            rapid_mod_threshold: Number of rapid modifications to trigger alert
            rapid_mod_window: Time window (seconds) for rapid modification detection
            extension_change_threshold: Number of extension changes to trigger alert
        """
        self.entropy_threshold = entropy_threshold
        self.rapid_mod_threshold = rapid_mod_threshold
        self.rapid_mod_window = rapid_mod_window
        self.extension_change_threshold = extension_change_threshold
        
        # Track modification timestamps per process
        # Structure: {pid: [(timestamp, operation_type, inode), ...]}
        self._modification_history: dict[int, list[tuple[float, str, int]]] = defaultdict(list)
        
        # Track extension changes
        # Structure: {pid: [(timestamp, old_ext, new_ext), ...]}
        self._extension_changes: dict[int, list[tuple[float, str, str]]] = defaultdict(list)
        
        # Track per-inode entropy history for pattern detection
        # Structure: {inode: [entropy_values]}
        self._entropy_history: dict[int, list[float]] = defaultdict(list)
        
        # Lock for thread safety
        self._lock = threading.Lock()
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of byte data.
        
        Shannon entropy measures the average information content per byte.
        - Random/encrypted data: ~7.5-8.0 bits/byte
        - Compressed data: ~6.0-7.5 bits/byte  
        - Plain text: ~4.0-5.0 bits/byte
        - Repetitive data: ~0.0-2.0 bits/byte
        
        Args:
            data: Byte buffer to analyze
            
        Returns:
            Entropy value in bits per byte (0.0 to 8.0)
        """
        if not data:
            return 0.0
        
        # Count frequency of each byte value (0-255)
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Calculate Shannon entropy: H = -Σ p(x) * log2(p(x))
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def get_file_extension(filename: str) -> str:
        """Extract file extension from filename."""
        if not filename:
            return ""
        # Handle bytes
        if isinstance(filename, bytes):
            filename = filename.decode('utf-8', errors='replace')
        # Find last dot
        dot_idx = filename.rfind('.')
        if dot_idx == -1 or dot_idx == 0:
            return ""
        return filename[dot_idx:].lower()
    
    def _cleanup_old_entries(self, pid: int, current_time: float) -> None:
        """Remove entries older than the analysis window."""
        # Cleanup modification history
        if pid in self._modification_history:
            cutoff = current_time - self.rapid_mod_window
            self._modification_history[pid] = [
                entry for entry in self._modification_history[pid]
                if entry[0] > cutoff
            ]
        
        # Cleanup extension changes (use longer window)
        if pid in self._extension_changes:
            cutoff = current_time - self.EXTENSION_CHANGE_WINDOW_SECONDS
            self._extension_changes[pid] = [
                entry for entry in self._extension_changes[pid]
                if entry[0] > cutoff
            ]
    
    def _analyze_entropy(self, data: bytes, inode: int) -> ThreatContext:
        """
        Analyze entropy of write data.
        
        High entropy indicates potentially encrypted data, which is a
        strong indicator of ransomware activity.
        """
        entropy = self.calculate_entropy(data)
        
        # Track entropy history for this inode
        with self._lock:
            self._entropy_history[inode].append(entropy)
            # Keep only last 10 values
            if len(self._entropy_history[inode]) > 10:
                self._entropy_history[inode] = self._entropy_history[inode][-10:]
        
        # Calculate confidence based on entropy level
        if entropy >= self.entropy_threshold:
            # High confidence: clearly encrypted data
            confidence = min(1.0, (entropy - 6.0) / 2.0)  # Scale 6.0-8.0 to 0.0-1.0
            return ThreatContext(
                threat_type=ThreatType.HIGH_ENTROPY_WRITE,
                confidence=confidence,
                details={
                    'entropy': entropy,
                    'threshold': self.entropy_threshold,
                    'data_size': len(data),
                    'inode': inode,
                }
            )
        elif entropy >= self.SUSPICIOUS_ENTROPY_THRESHOLD:
            # Medium confidence: possibly compressed or partially encrypted
            confidence = (entropy - self.SUSPICIOUS_ENTROPY_THRESHOLD) / (self.entropy_threshold - self.SUSPICIOUS_ENTROPY_THRESHOLD)
            confidence *= 0.5  # Cap at 0.5 for suspicious but not definitive
            return ThreatContext(
                threat_type=ThreatType.HIGH_ENTROPY_WRITE,
                confidence=confidence,
                details={
                    'entropy': entropy,
                    'threshold': self.entropy_threshold,
                    'data_size': len(data),
                    'inode': inode,
                    'note': 'suspicious_but_not_definitive',
                }
            )
        
        return ThreatContext(threat_type=ThreatType.NONE, confidence=0.0)
    
    def _analyze_frequency(self, ctx: OperationContext) -> ThreatContext:
        """
        Analyze modification frequency.
        
        Ransomware typically modifies many files in rapid succession.
        """
        pid = ctx.pid or 0
        current_time = ctx.timestamp
        
        with self._lock:
            self._cleanup_old_entries(pid, current_time)
            
            # Record this operation
            self._modification_history[pid].append(
                (current_time, ctx.operation, ctx.inode)
            )
            
            # Count recent operations
            recent_ops = len(self._modification_history[pid])
        
        if recent_ops >= self.rapid_mod_threshold:
            # Calculate confidence based on how much we exceed threshold
            confidence = min(1.0, recent_ops / (self.rapid_mod_threshold * 2))
            return ThreatContext(
                threat_type=ThreatType.RAPID_MODIFICATION,
                confidence=confidence,
                details={
                    'operation_count': recent_ops,
                    'threshold': self.rapid_mod_threshold,
                    'window_seconds': self.rapid_mod_window,
                    'pid': pid,
                }
            )
        
        return ThreatContext(threat_type=ThreatType.NONE, confidence=0.0)
    
    def _analyze_extension_change(self, old_name: str, new_name: str, pid: int) -> ThreatContext:
        """
        Analyze file extension changes.
        
        Ransomware often renames files with new extensions like .encrypted, .locked, etc.
        """
        old_ext = self.get_file_extension(old_name)
        new_ext = self.get_file_extension(new_name)
        
        # Skip if extensions are the same
        if old_ext == new_ext:
            return ThreatContext(threat_type=ThreatType.NONE, confidence=0.0)
        
        current_time = time.time()
        
        with self._lock:
            self._cleanup_old_entries(pid, current_time)
            
            # Record this extension change
            self._extension_changes[pid].append((current_time, old_ext, new_ext))
            
            # Count recent extension changes
            recent_changes = len(self._extension_changes[pid])
            
            # Check for suspicious extensions
            is_suspicious_ext = new_ext in self.SUSPICIOUS_EXTENSIONS
        
        # High confidence if using known ransomware extension
        if is_suspicious_ext:
            return ThreatContext(
                threat_type=ThreatType.MASS_EXTENSION_CHANGE,
                confidence=0.9,
                details={
                    'old_extension': old_ext,
                    'new_extension': new_ext,
                    'is_known_ransomware_extension': True,
                    'pid': pid,
                }
            )
        
        # Check for mass extension changes
        if recent_changes >= self.extension_change_threshold:
            confidence = min(1.0, recent_changes / (self.extension_change_threshold * 2))
            return ThreatContext(
                threat_type=ThreatType.MASS_EXTENSION_CHANGE,
                confidence=confidence,
                details={
                    'old_extension': old_ext,
                    'new_extension': new_ext,
                    'change_count': recent_changes,
                    'threshold': self.extension_change_threshold,
                    'pid': pid,
                }
            )
        
        return ThreatContext(threat_type=ThreatType.NONE, confidence=0.0)
    
    def _analyze_deletion(self, ctx: OperationContext) -> ThreatContext:
        """
        Analyze deletion patterns.
        
        Mass deletion after encryption is a common ransomware pattern.
        """
        pid = ctx.pid or 0
        current_time = ctx.timestamp
        
        with self._lock:
            self._cleanup_old_entries(pid, current_time)
            
            # Count recent deletions
            recent_deletions = sum(
                1 for entry in self._modification_history[pid]
                if entry[1] == 'unlink'
            )
        
        if recent_deletions >= self.rapid_mod_threshold:
            confidence = min(1.0, recent_deletions / (self.rapid_mod_threshold * 2))
            return ThreatContext(
                threat_type=ThreatType.MASS_DELETION,
                confidence=confidence,
                details={
                    'deletion_count': recent_deletions,
                    'threshold': self.rapid_mod_threshold,
                    'window_seconds': self.rapid_mod_window,
                    'pid': pid,
                }
            )
        
        return ThreatContext(threat_type=ThreatType.NONE, confidence=0.0)
    
    def analyze(self, ctx: OperationContext) -> ThreatContext:
        """
        Main analysis entry point.
        
        Analyzes an operation and returns the highest-confidence threat detected.
        
        Args:
            ctx: Context about the operation to analyze
            
        Returns:
            ThreatContext with the most significant threat detected
        """
        threats: list[ThreatContext] = []
        
        # Always check modification frequency
        freq_threat = self._analyze_frequency(ctx)
        if freq_threat.threat_type != ThreatType.NONE:
            threats.append(freq_threat)
        
        # Operation-specific analysis
        if ctx.operation == 'write' and ctx.data:
            # ENTROPY CHECK: This is where we analyze write data for encryption
            # High entropy (> 7.0 bits/byte) indicates potentially encrypted data
            entropy_threat = self._analyze_entropy(ctx.data, ctx.inode)
            if entropy_threat.threat_type != ThreatType.NONE:
                threats.append(entropy_threat)
        
        elif ctx.operation == 'rename' and ctx.old_name and ctx.new_name:
            ext_threat = self._analyze_extension_change(
                ctx.old_name, ctx.new_name, ctx.pid or 0
            )
            if ext_threat.threat_type != ThreatType.NONE:
                threats.append(ext_threat)
        
        elif ctx.operation == 'unlink':
            del_threat = self._analyze_deletion(ctx)
            if del_threat.threat_type != ThreatType.NONE:
                threats.append(del_threat)
        
        # Return highest confidence threat, or NONE
        if threats:
            return max(threats, key=lambda t: t.confidence)
        
        return ThreatContext(threat_type=ThreatType.NONE, confidence=0.0)
    
    def get_threat_score(self, ctx: OperationContext) -> float:
        """
        Get a simple threat score (0.0 to 1.0).
        
        Convenience method that returns just the confidence value.
        """
        threat = self.analyze(ctx)
        return threat.confidence
    
    def reset_stats(self, pid: Optional[int] = None) -> None:
        """
        Reset tracking statistics.
        
        Args:
            pid: If specified, only reset stats for this PID. Otherwise reset all.
        """
        with self._lock:
            if pid is not None:
                self._modification_history.pop(pid, None)
                self._extension_changes.pop(pid, None)
            else:
                self._modification_history.clear()
                self._extension_changes.clear()
                self._entropy_history.clear()
    
    def get_stats(self) -> dict:
        """Get current tracking statistics for debugging/monitoring."""
        with self._lock:
            return {
                'active_pids': list(self._modification_history.keys()),
                'total_tracked_operations': sum(
                    len(v) for v in self._modification_history.values()
                ),
                'total_extension_changes': sum(
                    len(v) for v in self._extension_changes.values()
                ),
                'tracked_inodes': len(self._entropy_history),
            }
