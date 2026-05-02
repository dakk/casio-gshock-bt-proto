#!/usr/bin/env python3
"""Find step count in 0x1e sport activity summary - protocol flow analysis"""

import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_2.log'

def run_tshark(*args):
    result = subprocess.run(['tshark', '-r', LOG] + list(args), capture_output=True, text=True)
    return result.stdout.strip()

def get_frames_by_handle(handle_hex):
    """Get all frames for a given handle"""
    out = run_tshark(
        '-Y', f'btatt.handle == {handle_hex}',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'btatt.opcode',
        '-e', 'btatt.value'
    )
    frames = []
    for line in out.split('\n'):
        parts = line.strip().split('\t')
        try:
            if len(parts) >= 3 and parts[2]:
                fno = int(parts[0])
                opcode = int(parts[1], 16) if parts[1] else 0
                data = bytes.fromhex(parts[2].replace(':', ''))
                frames.append((fno, opcode, data))
            elif len(parts) == 2 and parts[1]:
                fno = int(parts[0])
                data = bytes.fromhex(parts[1].replace(':', ''))
                frames.append((fno, 0, data))
        except (ValueError, IndexError):
            pass
    return frames

def xor_decode(data):
    result = bytearray(data)
    for i in range(1, len(result)):
        result[i] ^= 0xFF
    return bytes(result)

def hex_str(data, max_bytes=32):
    return ' '.join(f'{b:02x}' for b in data[:max_bytes])

print("=== Full protocol flow: handle 0x0011 (requests) + 0x0014 (CONVOY data) ===")
print()

# Get all frames on both handles
frames_0011 = get_frames_by_handle('0x0011')
frames_0014 = get_frames_by_handle('0x0014')

print(f"Handle 0x0011 frames: {len(frames_0011)}")
print(f"Handle 0x0014 frames: {len(frames_0014)}")
print()

# Merge and sort by frame number
all_frames = [(fno, '0011', opcode, data) for fno, opcode, data in frames_0011]
all_frames += [(fno, '0014', opcode, data) for fno, opcode, data in frames_0014]
all_frames.sort(key=lambda x: x[0])

print("=== Second connection (frames 5400-6000) protocol flow ===")
for fno, hdl, opcode, data in all_frames:
    if 5400 <= fno <= 6000:
        if hdl == '0011':
            print(f"  [{fno}] h0011: {hex_str(data)}")
        else:
            ptype = data[0]
            decoded = xor_decode(data)
            if ptype == 0x05:
                print(f"  [{fno}] h0014 type=05 raw: {hex_str(data,16)}")
                print(f"  [{fno}] h0014 type=05 dec: {hex_str(decoded,16)}")
            else:
                print(f"  [{fno}] h0014 type=0{ptype:x} raw: {hex_str(data,16)}")
print()

# Find the 0x1e data -- collect all type-0x05 frames following the 0x1e request
# The request is on h0011 with format: 00 1e 00 [offset_lo] [offset_hi] ...
print("=== Finding 0x1e feature requests ===")
for fno, hdl, opcode, data in all_frames:
    if hdl == '0011' and len(data) >= 2 and data[1] == 0x1e:
        print(f"  [{fno}] REQUEST 0x1e: {hex_str(data)}")

print()

# Collect the multi-frame 0x1e response
# After the 0x1e request, type-0x05 frames carry the data
print("=== Assembling 0x1e test session summary (after frame ~5480) ===")

# Find all type-0x05 convoy frames between the 0x1e request and the 0x1f request
collecting = False
assembled = bytearray()
frames_collected = []

for fno, hdl, opcode, data in all_frames:
    if hdl == '0011':
        if len(data) >= 2 and data[1] == 0x1e and fno > 5400:
            print(f"  START: frame {fno} 0x1e request: {hex_str(data)}")
            collecting = True
            assembled = bytearray()
            frames_collected = []
        elif len(data) >= 2 and data[1] == 0x1f and collecting:
            print(f"  STOP: frame {fno} 0x1f request (next feature)")
            collecting = False
        elif collecting and data[0] == 0x04:
            # ACK on request handle
            print(f"  [{fno}] h0011 ACK: {hex_str(data)}")
    elif hdl == '0014' and collecting:
        ptype = data[0]
        if ptype == 0x05:
            decoded = bytearray(xor_decode(data))
            # payload starts at byte 3 (skip type + 2-byte len)
            payload = decoded[3:]
            assembled.extend(payload)
            frames_collected.append(fno)
            print(f"  [{fno}] data chunk ({len(payload)} bytes)")
        elif ptype == 0x06:
            print(f"  [{fno}] h0014 type=06: {hex_str(data)}")

print(f"\nTotal assembled: {len(assembled)} bytes from frames {frames_collected}")
print()

if len(assembled) > 0:
    print("=== Full hex dump ===")
    for i in range(0, len(assembled), 16):
        chunk = assembled[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  [{i:3d}] {hex_part}")

    print()
    print("=== Search for step count ~1902 (tolerance ±200) ===")
    target = 1902
    for i in range(len(assembled) - 1):
        val16 = assembled[i] | (assembled[i+1] << 8)
        if abs(val16 - target) <= 200:
            print(f"  LE16 [{i}:{i+2}] = {val16} (0x{val16:04x})")
    for i in range(len(assembled) - 3):
        val32 = assembled[i] | (assembled[i+1] << 8) | (assembled[i+2] << 16) | (assembled[i+3] << 24)
        if abs(val32 - target) <= 200 and val32 <= 2200:
            print(f"  LE32 [{i}:{i+4}] = {val32} (0x{val32:08x})")

    print()
    print("=== Search for activity step count ~140 steps (78s @ 106 fpm) ===")
    for i in range(len(assembled) - 1):
        val16 = assembled[i] | (assembled[i+1] << 8)
        if 80 <= val16 <= 200:
            print(f"  LE16 [{i}:{i+2}] = {val16}")

    print()
    print("=== Bytes [164-200] (uncharted) ===")
    for i in range(164, min(210, len(assembled))):
        print(f"  [{i}] = 0x{assembled[i]:02x} = {assembled[i]}")
