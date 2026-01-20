# MimicFS - Ransomware-Defensive FUSE Filesystem

A Python FUSE-based filesystem that acts as an active defensive layer against ransomware attacks.

## Features

- **Threat Detection (Heuristic Analysis)**
  - Shannon entropy analysis on write data to detect encryption
  - Modification frequency tracking (rapid file changes)
  - Mass extension change detection (`.txt` → `.encrypted`)
  - Mass deletion pattern detection

- **Defense Mechanism (Micro-Snapshotting)**
  - Block-level Copy-on-Write (CoW) snapshots
  - Compressed storage using zlib
  - In-memory or persistent shadow storage
  - LRU eviction for memory management

- **Adaptive Response**
  - **Block**: Deny suspicious operations entirely
  - **Misdirect**: Redirect to honeypot files
  - **Log**: Comprehensive forensic logging

- **Recovery**
  - Restore files from micro-snapshots
  - Full file reconstruction from saved blocks

## Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install libfuse3-dev fuse3

# Fedora
sudo dnf install fuse3-devel fuse3

# Arch Linux
sudo pacman -S fuse3
```

### Python Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Mount the Filesystem

```bash
# Basic usage
python main.py /path/to/protect /path/to/mountpoint

# With custom thresholds
python main.py /data /mnt/secure \
    --block-threshold 0.7 \
    --misdirect-threshold 0.4 \
    --entropy-threshold 7.0

# With persistent shadow storage
python main.py /data /mnt/secure \
    --shadow-storage /var/lib/mimicfs/shadows \
    --log-file /var/log/mimicfs/forensic.log
```

### Unmount

```bash
# Press Ctrl+C in the terminal, or:
fusermount3 -u /path/to/mountpoint
```

### Restore a File

```bash
python main.py --restore /mnt/secure/infected_file.txt \
    --source /data \
    --shadow-storage /var/lib/mimicfs/shadows
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--block-threshold` | 0.8 | Confidence (0-1) to block operations |
| `--misdirect-threshold` | 0.5 | Confidence (0-1) to redirect to honeypot |
| `--entropy-threshold` | 7.0 | Entropy (0-8) to flag as suspicious |
| `--snapshot-memory` | 512 | Max memory (MB) for in-memory snapshots |
| `--shadow-storage` | None | Directory for persistent snapshots |
| `--block-size` | 4096 | Block size for snapshots |
| `--honeypot-dir` | .mimicfs_honeypot | Honeypot directory name |
| `--log-file` | None | Path to forensic log file |
| `--no-snapshots` | False | Disable snapshotting |
| `--no-honeypot` | False | Disable honeypot misdirection |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      User Application                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    MimicFS (FUSE Layer)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   write()   │  │  rename()   │  │     unlink()        │  │
│  │   chmod()   │  │             │  │                     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                    │              │
│         ▼                ▼                    ▼              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  ThreatAnalyzer                      │    │
│  │  • Shannon Entropy    • Modification Frequency      │    │
│  │  • Extension Changes  • Deletion Patterns           │    │
│  └─────────────────────────┬───────────────────────────┘    │
│                            │                                 │
│              ┌─────────────┼─────────────┐                  │
│              ▼             ▼             ▼                  │
│         ┌────────┐   ┌──────────┐   ┌────────┐             │
│         │ BLOCK  │   │MISDIRECT │   │ ALLOW  │             │
│         │ EACCES │   │ Honeypot │   │ + CoW  │             │
│         └────────┘   └──────────┘   └───┬────┘             │
│                                         │                   │
│                            ┌────────────▼────────────┐      │
│                            │   SnapshotManager       │      │
│                            │   (Block-level CoW)     │      │
│                            └────────────┬────────────┘      │
│                                         │                   │
│                            ┌────────────▼────────────┐      │
│                            │    ForensicLogger       │      │
│                            │    (JSON Logging)       │      │
│                            └─────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Underlying Filesystem                       │
└─────────────────────────────────────────────────────────────┘
```

## How Write Interception Works

```python
async def write(self, fh, offset, buf, ctx):
    """
    WRITE INTERCEPTION - CORE RANSOMWARE DEFENSE
    
    1. ENTROPY CHECK: Calculate Shannon entropy of buf
       - High entropy (>7.0 bits/byte) = encrypted data
    
    2. THREAT ANALYSIS: Combine with frequency + patterns
       - Returns confidence score 0.0 to 1.0
    
    3. SNAPSHOT (CoW): Save original blocks BEFORE write
       - Enables recovery if write is malicious
    
    4. ADAPTIVE RESPONSE:
       - Block (≥0.8): Deny with EACCES
       - Misdirect (≥0.5): Write to honeypot instead
       - Allow (<0.5): Proceed with snapshotted write
    """
```

## File Structure

```
MimicFs/
├── main.py              # Entry point with CLI
├── mimicfs.py           # Core FUSE filesystem class
├── threat_analyzer.py   # Heuristic threat detection
├── snapshot_manager.py  # Block-level CoW snapshots
├── forensic_logger.py   # Structured JSON logging
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## License

MIT License

## Security Considerations

- MimicFS is a **defensive layer**, not a replacement for backups
- Configure thresholds based on your use case to minimize false positives
- Review forensic logs regularly for tuning
- Honeypot files should be monitored and cleaned periodically
- Shadow storage should be on a separate volume if possible
