#!/usr/bin/env python3
"""
MimicFS - Ransomware-Defensive FUSE Filesystem

Main entry point for mounting and running MimicFS.

Usage:
    python main.py /path/to/protect /path/to/mountpoint [options]

Example:
    # Protect /home/user/documents, mount at /mnt/protected
    python main.py /home/user/documents /mnt/protected
    
    # With custom options
    python main.py /home/user/documents /mnt/protected \\
        --block-threshold 0.7 \\
        --log-file /var/log/mimicfs.log \\
        --shadow-storage /var/lib/mimicfs/shadows
"""

import argparse
import os
import sys
import signal
import logging
from pathlib import Path

try:
    import pyfuse3
    import trio
except ImportError as e:
    print(f"Error: Required dependency not found: {e}")
    print("Install dependencies with: pip install pyfuse3 trio")
    sys.exit(1)

from mimicfs import MimicFS, MimicFSConfig
from forensic_logger import ForensicLogger, EventType


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog='mimicfs',
        description='MimicFS - Ransomware-Defensive FUSE Filesystem',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  %(prog)s /home/user/documents /mnt/protected
  
  # With custom threat thresholds
  %(prog)s /data /mnt/secure --block-threshold 0.7 --misdirect-threshold 0.4
  
  # Enable debug logging
  %(prog)s /data /mnt/secure --debug --log-file /var/log/mimicfs/debug.log
  
  # With shadow storage for persistent snapshots
  %(prog)s /data /mnt/secure --shadow-storage /var/lib/mimicfs/shadows

Recovery:
  To restore a file after a ransomware attack, use the restore command:
  %(prog)s --restore /mnt/secure/infected_file.txt --source /data
        """,
    )
    
    # Positional arguments (for mount mode)
    parser.add_argument(
        'source',
        nargs='?',
        help='Source directory to protect',
    )
    parser.add_argument(
        'mountpoint',
        nargs='?',
        help='Mount point for the protected filesystem',
    )
    
    # Operational modes
    mode_group = parser.add_argument_group('Operational Modes')
    mode_group.add_argument(
        '--restore',
        metavar='PATH',
        help='Restore a file from snapshots instead of mounting',
    )
    mode_group.add_argument(
        '--list-snapshots',
        action='store_true',
        help='List available snapshots and exit',
    )
    mode_group.add_argument(
        '--stats',
        action='store_true',
        help='Show filesystem statistics and exit (requires running instance)',
    )
    
    # Threat detection thresholds
    threat_group = parser.add_argument_group('Threat Detection')
    threat_group.add_argument(
        '--block-threshold',
        type=float,
        default=0.8,
        metavar='FLOAT',
        help='Confidence threshold (0.0-1.0) to block operations (default: 0.8)',
    )
    threat_group.add_argument(
        '--misdirect-threshold',
        type=float,
        default=0.5,
        metavar='FLOAT',
        help='Confidence threshold (0.0-1.0) to misdirect to honeypot (default: 0.5)',
    )
    threat_group.add_argument(
        '--entropy-threshold',
        type=float,
        default=7.0,
        metavar='FLOAT',
        help='Entropy level (0.0-8.0) to flag as suspicious (default: 7.0)',
    )
    
    # Snapshot settings
    snapshot_group = parser.add_argument_group('Snapshot Settings')
    snapshot_group.add_argument(
        '--snapshot-memory',
        type=int,
        default=512,
        metavar='MB',
        help='Maximum memory for in-memory snapshots (default: 512 MB)',
    )
    snapshot_group.add_argument(
        '--shadow-storage',
        metavar='PATH',
        help='Directory for persistent shadow storage',
    )
    snapshot_group.add_argument(
        '--block-size',
        type=int,
        default=4096,
        metavar='BYTES',
        help='Block size for snapshots (default: 4096)',
    )
    snapshot_group.add_argument(
        '--no-snapshots',
        action='store_true',
        help='Disable snapshotting (not recommended)',
    )
    
    # Honeypot settings
    honeypot_group = parser.add_argument_group('Honeypot Settings')
    honeypot_group.add_argument(
        '--honeypot-dir',
        default='.mimicfs_honeypot',
        metavar='NAME',
        help='Name of honeypot directory (default: .mimicfs_honeypot)',
    )
    honeypot_group.add_argument(
        '--no-honeypot',
        action='store_true',
        help='Disable honeypot misdirection',
    )
    
    # Logging settings
    log_group = parser.add_argument_group('Logging')
    log_group.add_argument(
        '--log-file',
        metavar='PATH',
        help='Path to forensic log file',
    )
    log_group.add_argument(
        '--no-console',
        action='store_true',
        help='Disable console logging',
    )
    log_group.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output',
    )
    
    # FUSE options
    fuse_group = parser.add_argument_group('FUSE Options')
    fuse_group.add_argument(
        '--allow-other',
        action='store_true',
        help='Allow other users to access the filesystem',
    )
    fuse_group.add_argument(
        '--allow-root',
        action='store_true',
        help='Allow root to access the filesystem',
    )
    fuse_group.add_argument(
        '--foreground', '-f',
        action='store_true',
        help='Run in foreground (default)',
    )
    fuse_group.add_argument(
        '--fuse-debug',
        action='store_true',
        help='Enable FUSE debug output',
    )
    
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> bool:
    """Validate command-line arguments."""
    # Check for restore mode
    if args.restore:
        if not args.source:
            print("Error: --source is required for restore mode")
            return False
        return True
    
    # Check for mount mode
    if not args.source or not args.mountpoint:
        print("Error: source and mountpoint are required for mount mode")
        print("Use --help for usage information")
        return False
    
    # Validate source directory
    if not os.path.isdir(args.source):
        print(f"Error: Source directory does not exist: {args.source}")
        return False
    
    # Validate mountpoint
    if not os.path.isdir(args.mountpoint):
        print(f"Error: Mountpoint does not exist: {args.mountpoint}")
        return False
    
    # Check mountpoint is empty
    if os.listdir(args.mountpoint):
        print(f"Warning: Mountpoint is not empty: {args.mountpoint}")
    
    # Validate thresholds
    if not 0.0 <= args.block_threshold <= 1.0:
        print("Error: --block-threshold must be between 0.0 and 1.0")
        return False
    
    if not 0.0 <= args.misdirect_threshold <= 1.0:
        print("Error: --misdirect-threshold must be between 0.0 and 1.0")
        return False
    
    if not 0.0 <= args.entropy_threshold <= 8.0:
        print("Error: --entropy-threshold must be between 0.0 and 8.0")
        return False
    
    if args.misdirect_threshold >= args.block_threshold:
        print("Warning: misdirect-threshold should be less than block-threshold")
    
    return True


def create_config(args: argparse.Namespace) -> MimicFSConfig:
    """Create MimicFS configuration from arguments."""
    return MimicFSConfig(
        block_threshold=args.block_threshold,
        misdirect_threshold=args.misdirect_threshold,
        entropy_threshold=args.entropy_threshold,
        snapshot_max_memory_mb=args.snapshot_memory,
        shadow_storage_path=args.shadow_storage,
        block_size=args.block_size,
        honeypot_dir=args.honeypot_dir,
        log_file=args.log_file,
        console_logging=not args.no_console,
        enable_snapshots=not args.no_snapshots,
        enable_honeypot=not args.no_honeypot,
    )


def setup_logging(debug: bool) -> None:
    """Setup Python logging."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )


def restore_file(args: argparse.Namespace) -> int:
    """Restore a file from snapshots."""
    from snapshot_manager import SnapshotManager
    
    print(f"Attempting to restore: {args.restore}")
    
    # Try to find snapshot in shadow storage
    shadow_path = args.shadow_storage
    if not shadow_path:
        # Try default locations
        defaults = [
            os.path.join(args.source, '.mimicfs_shadows'),
            os.path.expanduser('~/.mimicfs/shadows'),
            '/var/lib/mimicfs/shadows',
        ]
        for path in defaults:
            if os.path.isdir(path):
                shadow_path = path
                break
    
    if not shadow_path or not os.path.isdir(shadow_path):
        print("Error: No shadow storage found. Specify with --shadow-storage")
        return 1
    
    print(f"Using shadow storage: {shadow_path}")
    
    manager = SnapshotManager(shadow_storage_path=shadow_path)
    
    # List available snapshots
    snapshots = manager.list_snapshots()
    if not snapshots:
        print("No snapshots found in shadow storage")
        return 1
    
    print(f"Found {len(snapshots)} snapshots:")
    for snap in snapshots:
        print(f"  - {snap['path']} ({snap['block_count']} blocks)")
    
    # Try to restore
    target_path = args.restore
    if manager.restore_file(target_path, target_path=target_path):
        print(f"Successfully restored: {target_path}")
        return 0
    else:
        print(f"Failed to restore: {target_path}")
        return 1


async def run_filesystem(fs: MimicFS, args: argparse.Namespace) -> None:
    """Run the FUSE filesystem event loop."""
    try:
        await pyfuse3.main()
    except Exception as e:
        import traceback
        logging.error(f"Filesystem error: {e}")
        logging.error(f"Full traceback:\n{traceback.format_exc()}")
        raise


def main() -> int:
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    setup_logging(args.debug)
    logger = logging.getLogger('MimicFS')
    
    # Handle restore mode
    if args.restore:
        return restore_file(args)
    
    # Validate arguments
    if not validate_args(args):
        return 1
    
    # Create configuration
    config = create_config(args)
    
    # Create filesystem
    try:
        fs = MimicFS(
            source_dir=os.path.abspath(args.source),
            config=config,
        )
    except Exception as e:
        logger.error(f"Failed to create filesystem: {e}")
        return 1
    
    # Build FUSE options
    fuse_options = set(pyfuse3.default_options)
    fuse_options.add(f'fsname=mimicfs:{args.source}')
    fuse_options.add('default_permissions')
    
    if args.allow_other:
        fuse_options.add('allow_other')
    if args.allow_root:
        fuse_options.add('allow_root')
    if args.fuse_debug:
        fuse_options.add('debug')
    
    # Initialize FUSE
    mountpoint = os.path.abspath(args.mountpoint)
    
    try:
        pyfuse3.init(fs, mountpoint, fuse_options)
    except Exception as e:
        logger.error(f"Failed to initialize FUSE: {e}")
        return 1
    
    # Track if we've already closed
    closed = False
    
    # Setup signal handlers for clean shutdown
    def signal_handler(signum, frame):
        nonlocal closed
        if closed:
            return
        logger.info(f"Received signal {signum}, shutting down...")
        closed = True
        pyfuse3.terminate()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Print startup message
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                        MimicFS v1.0                          ║
║           Ransomware-Defensive FUSE Filesystem               ║
╠══════════════════════════════════════════════════════════════╣
║  Source:     {args.source:<46} ║
║  Mountpoint: {mountpoint:<46} ║
║  Block threshold:    {config.block_threshold:<40} ║
║  Misdirect threshold: {config.misdirect_threshold:<39} ║
║  Entropy threshold:  {config.entropy_threshold:<40} ║
║  Snapshots: {'Enabled' if config.enable_snapshots else 'Disabled':<47} ║
║  Honeypot:  {'Enabled' if config.enable_honeypot else 'Disabled':<47} ║
╚══════════════════════════════════════════════════════════════╝
    
Press Ctrl+C to unmount and exit.
""")
    
    # Run the filesystem
    try:
        trio.run(run_filesystem, fs, args)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Filesystem error: {e}")
        return 1
    finally:
        # Cleanup - only close once
        if not closed:
            try:
                fs.logger.log_system_event(
                    EventType.FILESYSTEM_UNMOUNTED,
                    f"MimicFS unmounted: {mountpoint}",
                )
            except:
                pass
            
            try:
                pyfuse3.close(unmount=True)
            except:
                pass
        
        logger.info("Filesystem unmounted")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
