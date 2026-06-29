# Argus Eye v1.1

Network camera detector + interaction toolkit for iSH, Alpine, Termux, and Kali Linux.

## Features
- Auto subnet scan (21 camera ports)
- Banner grabbing & fingerprinting
- RTSP stream discovery
- Snapshot extraction (JPEG)
- Default credential testing
- ONVIF probing

## Install
```bash
apk add python3
python3 argus_eye.py
```

## Usage
```
[1] Network Scan     - auto-detect subnet, scan all hosts
[2] Manual Target    - interact with known camera IP
[3] Quick Port Check - single IP, all ports
[0] Exit
```

## Legal
For authorized security testing only.
