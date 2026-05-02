#!/usr/bin/env python3
"""Find step count ~1902 in the 0x1e sport activity summary from btsnoop_hci_2.log"""

import subprocess
import sys

def xor_decode(data):
    """Decode type-0x05 CONVOY packet: XOR all bytes[1:] with 0xFF"""
    result = bytearray(data)
    for i in range(1, len(result)):
        result[i] ^= 0xFF
    return bytes(result)

def get_convoy_data(log_path, frame_no):
    """Extract CONVOY handle 0x0014 data from a specific frame"""
    cmd = [
        'tshark', '-r', log_path,
        '-Y', f'frame.number == {frame_no}',
        '-T', 'fields',
        '-e', 'btatt.value'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    val = result.stdout.strip()
    if not val:
        return None
    return bytes.fromhex(val.replace(':', ''))

def get_all_convoy_frames(log_path):
    """Get all CONVOY (handle 0x0014) frames"""
    cmd = [
        'tshark', '-r', log_path,
        '-Y', 'btatt.handle == 0x0014',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'btatt.value'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    frames = []
    for line in result.stdout.strip().split('\n'):
        parts = line.strip().split('\t')
        if len(parts) == 2 and parts[1]:
            fno = int(parts[0])
            data = bytes.fromhex(parts[1].replace(':', ''))
            frames.append((fno, data))
    return frames

def collect_1e_chunks(frames):
    """
    Collect all type-0x05 CONVOY chunks that belong to a 0x1e (session summary) response.
    Groups consecutive chunks into sessions.
    """
    # We need to find the 0x06 control frames that precede 0x1e data
    # Type 0x06 = unencoded control, Type 0x05 = XOR'd data
    sessions = []
    current_session = None
    in_1e_session = False

    for fno, raw in frames:
        ptype = raw[0]

        if ptype == 0x06:
            # Control frame - check if it starts a 0x1e response
            # 0x06 frames are not XOR'd
            if len(raw) >= 2 and raw[1] == 0x1e:
                # This is a 0x1e session summary control frame
                if current_session is not None:
                    sessions.append(current_session)
                current_session = {'control': (fno, raw), 'data_frames': [], 'assembled': bytearray()}
                in_1e_session = True
            else:
                # Different control frame - end current session
                if current_session is not None:
                    sessions.append(current_session)
                    current_session = None
                in_1e_session = False
        elif ptype == 0x05 and in_1e_session:
            # Data chunk for current session
            decoded = xor_decode(raw)
            # Skip type byte (0x05) and 2-byte length header
            current_session['data_frames'].append((fno, decoded))
            current_session['assembled'].extend(decoded[3:])  # skip type + 2 len bytes

    if current_session is not None:
        sessions.append(current_session)

    return sessions

def search_value_in_data(data, target, tolerance=150):
    """Search for target value as LE16 and LE32 in data"""
    results = []
    lo = target - tolerance
    hi = target + tolerance

    # LE16
    for i in range(len(data) - 1):
        val = data[i] | (data[i+1] << 8)
        if lo <= val <= hi:
            results.append((i, 'LE16', val))

    # LE32
    for i in range(len(data) - 3):
        val = data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24)
        if lo <= val <= hi:
            results.append((i, 'LE32', val))

    return results

def main():
    log_path = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_2.log'

    print("=== Loading all CONVOY frames ===")
    frames = get_all_convoy_frames(log_path)
    print(f"Total CONVOY frames: {len(frames)}")

    print("\n=== Collecting 0x06 control frames ===")
    for fno, raw in frames:
        if raw[0] == 0x06:
            hex_str = ' '.join(f'{b:02x}' for b in raw[:min(20, len(raw))])
            print(f"  Frame {fno}: {hex_str}")

    print("\n=== Looking at 0x1e summary frames directly ===")
    # Find frames where first byte is 0x06 and second byte is 0x1e
    for fno, raw in frames:
        if raw[0] == 0x06 and len(raw) > 1 and raw[1] == 0x1e:
            print(f"  Frame {fno} (0x1e control): {' '.join(f'{b:02x}' for b in raw)}")

    print("\n=== Assembling 0x1e session summaries ===")
    # Find the test session (known to be around frame 5483)
    # Let's look at all CONVOY frames around frame 5483
    target_frame = 5483
    nearby = [(fno, raw) for fno, raw in frames if abs(fno - target_frame) < 200]

    print(f"\nFrames near {target_frame}:")
    for fno, raw in nearby[:30]:
        ptype = raw[0]
        hex_str = ' '.join(f'{b:02x}' for b in raw[:min(16, len(raw))])
        print(f"  Frame {fno} type=0x{ptype:02x}: {hex_str}")

    print("\n=== Assembling test session 0x1e data ===")
    # Based on prior analysis, test session 0x1e starts around frame 5483
    # Let's collect consecutive 0x05 frames after the 0x06 control frame

    assembled = bytearray()
    collecting = False

    for fno, raw in frames:
        ptype = raw[0]
        if ptype == 0x06 and len(raw) > 1 and raw[1] == 0x1e:
            if fno >= 5400 and fno <= 5550:
                print(f"  Starting collection at frame {fno}")
                collecting = True
                assembled = bytearray()
                continue

        if collecting:
            if ptype == 0x05:
                decoded = bytearray(xor_decode(raw))
                # Frame structure: [0]=type, [1:3]=payload_len LE16, [3:]=payload
                payload = decoded[3:]
                assembled.extend(payload)
                print(f"  Frame {fno}: appended {len(payload)} bytes (total={len(assembled)})")
            elif ptype == 0x06:
                print(f"  Frame {fno}: 0x06 control, stopping collection")
                collecting = False
                break

    print(f"\nAssembled data: {len(assembled)} bytes")

    if len(assembled) > 0:
        print("\n=== Full assembled hex dump ===")
        for i in range(0, len(assembled), 16):
            chunk = assembled[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"  [{i:3d}] {hex_part:<48}  {ascii_part}")

        print("\n=== Searching for step count ~1902 (tolerance ±150) ===")
        hits = search_value_in_data(assembled, 1902, tolerance=150)
        if hits:
            for offset, enc, val in hits:
                print(f"  [{offset}] {enc} = {val} (0x{val:04x})")
        else:
            print("  No matches found")

        print("\n=== Searching for small step counts (activity duration ~78s @ 106 fpm = ~137 steps) ===")
        hits2 = search_value_in_data(assembled, 137, tolerance=50)
        if hits2:
            for offset, enc, val in hits2:
                # Filter out obvious non-step values
                if enc == 'LE16' or (enc == 'LE32' and val < 300):
                    print(f"  [{offset}] {enc} = {val} (0x{val:04x})")

        print("\n=== Known field values for reference ===")
        print(f"  [131] avg pace min = 0x{assembled[131]:02x} = {assembled[131]}")
        print(f"  [132] avg pace sec = 0x{assembled[132]:02x} = {assembled[132]}")
        print(f"  [181] calories     = 0x{assembled[181]:02x} = {assembled[181]}")
        print(f"  [185] cadence      = 0x{assembled[185]:02x} = {assembled[185]}")

        # Show unknown bytes in ranges that haven't been decoded
        print("\n=== Bytes 164-200 (uncharted territory) ===")
        for i in range(164, min(201, len(assembled))):
            print(f"  [{i}] = 0x{assembled[i]:02x} = {assembled[i]}")

if __name__ == '__main__':
    main()
