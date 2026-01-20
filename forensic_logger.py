"""
ForensicLogger - Structured logging for ransomware incident forensics.

This module provides comprehensive logging for:
1. Detected threats with full context
2. Blocked operations
3. Honeypot redirections
4. System events and recovery actions
"""

import json
import time
import os
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Any, Dict, List
import logging
from logging.handlers import RotatingFileHandler


class LogLevel(Enum):
    """Log severity levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ALERT = "ALERT"  # Suspicious activity
    CRITICAL = "CRITICAL"  # Confirmed threat / blocked operation


class EventType(Enum):
    """Types of events that can be logged."""
    # Threat detection events
    THREAT_DETECTED = "threat_detected"
    HIGH_ENTROPY_WRITE = "high_entropy_write"
    RAPID_MODIFICATION = "rapid_modification"
    MASS_EXTENSION_CHANGE = "mass_extension_change"
    MASS_DELETION = "mass_deletion"
    
    # Response events
    OPERATION_BLOCKED = "operation_blocked"
    OPERATION_MISDIRECTED = "operation_misdirected"
    HONEYPOT_WRITE = "honeypot_write"
    
    # Snapshot events
    SNAPSHOT_CREATED = "snapshot_created"
    SNAPSHOT_RESTORED = "snapshot_restored"
    SNAPSHOT_EVICTED = "snapshot_evicted"
    
    # System events
    FILESYSTEM_MOUNTED = "filesystem_mounted"
    FILESYSTEM_UNMOUNTED = "filesystem_unmounted"
    CONFIG_CHANGED = "config_changed"
    ERROR = "error"


@dataclass
class ForensicEvent:
    """
    Structured forensic event record.
    
    Contains all relevant information for incident investigation.
    """
    timestamp: float
    event_type: str
    level: str
    
    # Process information
    pid: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    process_name: Optional[str] = None
    
    # Operation details
    operation: Optional[str] = None
    path: Optional[str] = None
    inode: Optional[int] = None
    
    # Threat analysis
    threat_type: Optional[str] = None
    confidence: Optional[float] = None
    entropy: Optional[float] = None
    
    # Response action
    action_taken: Optional[str] = None
    honeypot_path: Optional[str] = None
    
    # Additional context
    details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        # Add human-readable timestamp
        d['timestamp_iso'] = datetime.fromtimestamp(self.timestamp).isoformat()
        # Remove None values for cleaner output
        return {k: v for k, v in d.items() if v is not None}
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class ForensicLogger:
    """
    Forensic logging system for MimicFS.
    
    Features:
    - Structured JSON logging for machine parsing
    - Human-readable console output
    - Log rotation to prevent disk exhaustion
    - Real-time alerting hooks
    - Query interface for recent events
    """
    
    DEFAULT_LOG_FILE = "/var/log/mimicfs/forensic.log"
    DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50MB per log file
    DEFAULT_BACKUP_COUNT = 10  # Keep 10 rotated files
    
    def __init__(
        self,
        log_file: Optional[str] = None,
        console_output: bool = True,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
        min_level: LogLevel = LogLevel.INFO,
    ):
        """
        Initialize the ForensicLogger.
        
        Args:
            log_file: Path to log file (None for default or no file logging)
            console_output: Whether to output to console
            max_bytes: Maximum size per log file before rotation
            backup_count: Number of rotated log files to keep
            min_level: Minimum log level to record
        """
        self.log_file = log_file
        self.console_output = console_output
        self.min_level = min_level
        
        # In-memory event buffer for recent events query
        self._event_buffer: List[ForensicEvent] = []
        self._buffer_max_size = 1000
        self._buffer_lock = threading.Lock()
        
        # Setup Python logger
        self._logger = logging.getLogger("MimicFS.Forensic")
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()
        
        # Console handler
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self._level_to_logging(min_level))
            console_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)
            self._logger.addHandler(console_handler)
        
        # File handler with rotation
        if log_file:
            try:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                
                file_handler = RotatingFileHandler(
                    log_file,
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                )
                file_handler.setLevel(logging.DEBUG)
                # JSON format for file
                file_handler.setFormatter(logging.Formatter('%(message)s'))
                self._logger.addHandler(file_handler)
            except PermissionError:
                # Fall back to user-writable location
                fallback_path = Path.home() / ".mimicfs" / "forensic.log"
                fallback_path.parent.mkdir(parents=True, exist_ok=True)
                self.log_file = str(fallback_path)
                
                file_handler = RotatingFileHandler(
                    self.log_file,
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                )
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(logging.Formatter('%(message)s'))
                self._logger.addHandler(file_handler)
        
        # Alert callbacks
        self._alert_callbacks: List[callable] = []
    
    @staticmethod
    def _level_to_logging(level: LogLevel) -> int:
        """Convert LogLevel to Python logging level."""
        mapping = {
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ALERT: logging.WARNING,
            LogLevel.CRITICAL: logging.CRITICAL,
        }
        return mapping.get(level, logging.INFO)
    
    def _add_to_buffer(self, event: ForensicEvent) -> None:
        """Add event to in-memory buffer."""
        with self._buffer_lock:
            self._event_buffer.append(event)
            # Trim buffer if too large
            if len(self._event_buffer) > self._buffer_max_size:
                self._event_buffer = self._event_buffer[-self._buffer_max_size:]
    
    def _format_console_message(self, event: ForensicEvent) -> str:
        """Format event for human-readable console output."""
        parts = [f"[{event.event_type}]"]
        
        if event.operation:
            parts.append(f"op={event.operation}")
        if event.path:
            parts.append(f"path={event.path}")
        if event.pid:
            parts.append(f"pid={event.pid}")
        if event.confidence is not None:
            parts.append(f"confidence={event.confidence:.2f}")
        if event.entropy is not None:
            parts.append(f"entropy={event.entropy:.2f}")
        if event.action_taken:
            parts.append(f"action={event.action_taken}")
        
        return " ".join(parts)
    
    def _trigger_alerts(self, event: ForensicEvent) -> None:
        """Trigger registered alert callbacks for high-severity events."""
        if event.level in (LogLevel.ALERT.value, LogLevel.CRITICAL.value):
            for callback in self._alert_callbacks:
                try:
                    callback(event)
                except Exception:
                    pass  # Don't let callback errors affect logging
    
    def log(self, event: ForensicEvent) -> None:
        """
        Log a forensic event.
        
        Args:
            event: The event to log
        """
        # Add to buffer
        self._add_to_buffer(event)
        
        # Get logging level
        level_map = {
            LogLevel.DEBUG.value: logging.DEBUG,
            LogLevel.INFO.value: logging.INFO,
            LogLevel.WARNING.value: logging.WARNING,
            LogLevel.ALERT.value: logging.WARNING,
            LogLevel.CRITICAL.value: logging.CRITICAL,
        }
        log_level = level_map.get(event.level, logging.INFO)
        
        # Log to file (JSON) and console (human-readable)
        if self.log_file:
            # For file: log JSON directly
            self._logger.log(log_level, event.to_json())
        
        if self.console_output:
            console_msg = self._format_console_message(event)
            self._logger.log(log_level, console_msg)
        
        # Trigger alerts
        self._trigger_alerts(event)
    
    def log_threat(
        self,
        threat_type: str,
        confidence: float,
        operation: str,
        path: str,
        inode: int,
        pid: Optional[int] = None,
        uid: Optional[int] = None,
        entropy: Optional[float] = None,
        details: Optional[dict] = None,
    ) -> None:
        """
        Log a detected threat.
        
        Args:
            threat_type: Type of threat detected
            confidence: Confidence score (0.0 to 1.0)
            operation: Operation that triggered detection
            path: File path involved
            inode: File inode
            pid: Process ID
            uid: User ID
            entropy: Entropy value if applicable
            details: Additional details
        """
        level = LogLevel.CRITICAL if confidence >= 0.7 else LogLevel.ALERT
        
        event = ForensicEvent(
            timestamp=time.time(),
            event_type=EventType.THREAT_DETECTED.value,
            level=level.value,
            pid=pid,
            uid=uid,
            operation=operation,
            path=path,
            inode=inode,
            threat_type=threat_type,
            confidence=confidence,
            entropy=entropy,
            details=details,
        )
        self.log(event)
    
    def log_blocked_operation(
        self,
        operation: str,
        path: str,
        inode: int,
        pid: Optional[int] = None,
        uid: Optional[int] = None,
        reason: str = "",
        threat_confidence: float = 0.0,
    ) -> None:
        """
        Log a blocked operation.
        
        Args:
            operation: The operation that was blocked
            path: File path
            inode: File inode
            pid: Process ID
            uid: User ID
            reason: Why the operation was blocked
            threat_confidence: Confidence score that led to blocking
        """
        event = ForensicEvent(
            timestamp=time.time(),
            event_type=EventType.OPERATION_BLOCKED.value,
            level=LogLevel.CRITICAL.value,
            pid=pid,
            uid=uid,
            operation=operation,
            path=path,
            inode=inode,
            action_taken="blocked",
            confidence=threat_confidence,
            details={"reason": reason},
        )
        self.log(event)
    
    def log_misdirection(
        self,
        operation: str,
        original_path: str,
        honeypot_path: str,
        inode: int,
        pid: Optional[int] = None,
        uid: Optional[int] = None,
    ) -> None:
        """
        Log a misdirected operation (honeypot redirect).
        
        Args:
            operation: The operation type
            original_path: Original target path
            honeypot_path: Honeypot path used instead
            inode: File inode
            pid: Process ID
            uid: User ID
        """
        event = ForensicEvent(
            timestamp=time.time(),
            event_type=EventType.OPERATION_MISDIRECTED.value,
            level=LogLevel.ALERT.value,
            pid=pid,
            uid=uid,
            operation=operation,
            path=original_path,
            inode=inode,
            action_taken="misdirected",
            honeypot_path=honeypot_path,
        )
        self.log(event)
    
    def log_snapshot(
        self,
        event_type: EventType,
        path: str,
        inode: int,
        blocks_count: int = 0,
        size_bytes: int = 0,
    ) -> None:
        """
        Log a snapshot event.
        
        Args:
            event_type: SNAPSHOT_CREATED, SNAPSHOT_RESTORED, or SNAPSHOT_EVICTED
            path: File path
            inode: File inode
            blocks_count: Number of blocks involved
            size_bytes: Size in bytes
        """
        event = ForensicEvent(
            timestamp=time.time(),
            event_type=event_type.value,
            level=LogLevel.INFO.value,
            path=path,
            inode=inode,
            details={
                "blocks_count": blocks_count,
                "size_bytes": size_bytes,
            },
        )
        self.log(event)
    
    def log_system_event(
        self,
        event_type: EventType,
        message: str,
        details: Optional[dict] = None,
    ) -> None:
        """
        Log a system event.
        
        Args:
            event_type: Event type
            message: Human-readable message
            details: Additional details
        """
        event = ForensicEvent(
            timestamp=time.time(),
            event_type=event_type.value,
            level=LogLevel.INFO.value,
            details={"message": message, **(details or {})},
        )
        self.log(event)
    
    def log_error(
        self,
        message: str,
        exception: Optional[Exception] = None,
        details: Optional[dict] = None,
    ) -> None:
        """
        Log an error.
        
        Args:
            message: Error message
            exception: Optional exception object
            details: Additional details
        """
        error_details = {"message": message}
        if exception:
            error_details["exception_type"] = type(exception).__name__
            error_details["exception_message"] = str(exception)
        if details:
            error_details.update(details)
        
        event = ForensicEvent(
            timestamp=time.time(),
            event_type=EventType.ERROR.value,
            level=LogLevel.WARNING.value,
            details=error_details,
        )
        self.log(event)
    
    def register_alert_callback(self, callback: callable) -> None:
        """
        Register a callback for high-severity alerts.
        
        The callback will be called with a ForensicEvent for any
        ALERT or CRITICAL level events.
        
        Args:
            callback: Function that accepts a ForensicEvent
        """
        self._alert_callbacks.append(callback)
    
    def unregister_alert_callback(self, callback: callable) -> None:
        """Remove a previously registered alert callback."""
        if callback in self._alert_callbacks:
            self._alert_callbacks.remove(callback)
    
    def get_recent_events(
        self,
        count: int = 100,
        event_type: Optional[EventType] = None,
        min_level: Optional[LogLevel] = None,
        since_timestamp: Optional[float] = None,
    ) -> List[ForensicEvent]:
        """
        Query recent events from the in-memory buffer.
        
        Args:
            count: Maximum number of events to return
            event_type: Filter by event type
            min_level: Filter by minimum severity level
            since_timestamp: Only return events after this timestamp
            
        Returns:
            List of matching ForensicEvent objects
        """
        level_order = {
            LogLevel.DEBUG.value: 0,
            LogLevel.INFO.value: 1,
            LogLevel.WARNING.value: 2,
            LogLevel.ALERT.value: 3,
            LogLevel.CRITICAL.value: 4,
        }
        
        with self._buffer_lock:
            events = list(self._event_buffer)
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type.value]
        
        if min_level:
            min_order = level_order.get(min_level.value, 0)
            events = [e for e in events if level_order.get(e.level, 0) >= min_order]
        
        if since_timestamp:
            events = [e for e in events if e.timestamp >= since_timestamp]
        
        # Return most recent
        return events[-count:]
    
    def get_threat_summary(self, hours: float = 24.0) -> dict:
        """
        Get a summary of threats detected in the specified time period.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with threat statistics
        """
        since = time.time() - (hours * 3600)
        events = self.get_recent_events(
            count=self._buffer_max_size,
            min_level=LogLevel.ALERT,
            since_timestamp=since,
        )
        
        threat_counts: Dict[str, int] = {}
        blocked_count = 0
        misdirected_count = 0
        unique_pids: set = set()
        
        for event in events:
            if event.threat_type:
                threat_counts[event.threat_type] = threat_counts.get(event.threat_type, 0) + 1
            if event.event_type == EventType.OPERATION_BLOCKED.value:
                blocked_count += 1
            if event.event_type == EventType.OPERATION_MISDIRECTED.value:
                misdirected_count += 1
            if event.pid:
                unique_pids.add(event.pid)
        
        return {
            "period_hours": hours,
            "total_alerts": len(events),
            "threats_by_type": threat_counts,
            "operations_blocked": blocked_count,
            "operations_misdirected": misdirected_count,
            "unique_suspicious_pids": list(unique_pids),
        }
