#!/usr/bin/env python3
"""
Extracts ALL frames on h0011 and h0014 in the range of track-related
activity downloads (0x1f requests to 0x20 ACK) from btsnoop_hci_3.log.
"""

import subprocess
import sys
import json

LOG = "/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log"

# First: dump ALL btatt frames with full data to find the range
cmd = [
    "tshark", "-r", LOG,
    "-Y", "btatt",
    "-T", "fields",
    "-e", "frame.number",
    "-e", "frame.time_relative",
    "-e", "bthci_acl.direction",
    "-e", "btatt.opcode",
    "-e", "btatt.handle",
    "-e", "btatt.value",
    "-E", "separator=|",
]

result = subprocess.run(cmd, capture_output=True, text=True)
if result.returncode != 0:
    print("tshark error:", result.stderr)
    sys.exit(1)

lines = result.stdout.strip().split('\n')
print(f"Total btatt frames: {len(lines)}")

# Parse and filter
frames = []
for line in lines:
    if not line.strip():
        continue
    parts = line.split('|')
    if len(parts) < 6:
        continue
    fnum = parts[0].strip()
    ftime = parts[1].strip()
    direction = parts[2].strip()  # 0=host->controller, 1=controller->host
    opcode = parts[3].strip()
    handle = parts[4].strip()
    value = parts[5].strip()
    frames.append({
        'num': int(fnum),
        'time': ftime,
        'dir': direction,
        'opcode': opcode,
        'handle': handle,
        'value': value,
    })

print(f"Parsed frames: {len(frames)}")

# Find handle values - need to identify which numeric handles correspond to h0011 and h0014
# h0011 = 0x0011 = 17 decimal
# h0014 = 0x0014 = 20 decimal
H0011 = '0x0011'
H0014 = '0x0014'

# Print all unique handles to understand
handles_seen = set()
for f in frames:
    handles_seen.add(f['handle'])
print("Handles seen:", sorted(handles_seen))

# Filter for frames on h0011 or h0014
track_frames = [f for f in frames if f['handle'] in (H0011, H0014)]
print(f"Frames on h0011 or h0014: {len(track_frames)}")

if not track_frames:
    # Maybe handles are decimal
    print("Trying decimal handles...")
    track_frames = [f for f in frames if f['handle'] in ('17', '20', '11', '14')]
    print(f"Found: {len(track_frames)}")
    for f in track_frames[:5]:
        print(f)
