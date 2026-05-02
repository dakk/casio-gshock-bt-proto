#!/usr/bin/env python3
"""Search for step count value in BLE captures"""
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_2.log'

def get_frame(frame_no):
    res = subprocess.run(['tshark','-r',LOG,'-Y',f'frame.number == {frame_no}','-T','fields','-e','btatt.value'], capture_output=True, text=True)
    return bytes.fromhex(res.stdout.strip().replace(':',''))

def xor_decode(data):
    d = bytearray(data)
    for i in range(1, len(d)):
        d[i] ^= 0xFF
    return bytes(d)

def get_all_convoy():
    result = subprocess.run(['tshark','-r',LOG,'-Y','btatt.handle == 0x0014','-T','fields','-e','frame.number','-e','btatt.value'], capture_output=True, text=True)
    frames = []
    for line in result.stdout.strip().split('\n'):
        parts = line.strip().split('\t')
        if len(parts) < 2 or not parts[1]:
            continue
        try:
            fno = int(parts[0])
            raw = bytes.fromhex(parts[1].replace(':',''))
            frames.append((fno, raw))
        except Exception:
            pass
    return frames

print("=== Search for step count ~1902 in ALL CONVOY type-0x05 frames ===")
frames = get_all_convoy()
for fno, raw in frames:
    if raw[0] != 0x05:
        continue
    dec = xor_decode(raw)
    for i in range(len(dec)-1):
        v16 = dec[i] | (dec[i+1] << 8)
        if 1700 <= v16 <= 2200:
            print(f"  Frame {fno}: LE16 [{i}] = {v16} (raw: {raw[i]:02x} {raw[i+1]:02x})")
    for i in range(len(dec)-3):
        v32 = dec[i] | (dec[i+1]<<8) | (dec[i+2]<<16) | (dec[i+3]<<24)
        if 1700 <= v32 <= 2200:
            print(f"  Frame {fno}: LE32 [{i}] = {v32}")

print()
print("=== Analyzing 0x1e summary payload (frame 5483) ===")
raw5483 = get_frame(5483)
dec5483 = xor_decode(raw5483)
payload = dec5483[3:]
print(f"Payload size: {len(payload)}")

print("\nMax pace check (10min54sec = 654 s/km):")
print(f"  payload[130]={payload[130]} payload[131]={payload[131]}")
print(f"  LE16[130:132] = {payload[130]|(payload[131]<<8)}")
print(f"  payload[174]={payload[174]} payload[175]={payload[175]} payload[176]={payload[176]}")

# Look for 654 in payload
print("\nSearching for 654 (max pace s/km):")
for i in range(110, 200):
    if i+1 < len(payload):
        v16 = payload[i]|(payload[i+1]<<8)
        if v16 == 654:
            print(f"  LE16[{i}:{i+2}] = {v16}")
    if payload[i] == 654 % 256 and i > 110:
        pass  # too many false positives

# Look for duration 78 seconds
print("\nSearching for duration 78s:")
for i in range(100, 200):
    if payload[i] == 78:
        print(f"  payload[{i}] = 78")
    if i+1 < len(payload):
        v16 = payload[i]|(payload[i+1]<<8)
        if v16 == 78:
            print(f"  LE16[{i}:{i+2}] = 78")

# Look for distance 60m
print("\nSearching for distance 60m:")
for i in range(100, 200):
    if payload[i] == 60:
        print(f"  payload[{i}] = 60")
    if i+1 < len(payload):
        v16 = payload[i]|(payload[i+1]<<8)
        if v16 == 60:
            print(f"  LE16[{i}:{i+2}] = 60")

# Activity step count ~138 steps
print("\nSearching for activity step count ~138 steps:")
for i in range(100, 200):
    if 120 <= payload[i] <= 160:
        print(f"  payload[{i}] = {payload[i]}")
    if i+1 < len(payload):
        v16 = payload[i]|(payload[i+1]<<8)
        if 120 <= v16 <= 160:
            print(f"  LE16[{i}:{i+2}] = {v16}")

# Check daily total step count at end of payload
print("\nChecking payload end bytes [240:256]:")
for i in range(240, len(payload)):
    print(f"  payload[{i}] = 0x{payload[i]:02x} = {payload[i]}")

print()
print("=== Summarizing all non-ff/non-zero bytes and their values ===")
for i in range(len(payload)):
    b = payload[i]
    if b != 0x00 and b != 0xFF:
        print(f"  payload[{i:3d}] (data[{i+3:3d}]) = 0x{b:02x} = {b}")
