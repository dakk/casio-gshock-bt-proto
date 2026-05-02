#!/usr/bin/env python3
"""
Full chronological analysis of track-related frames on h0011 and h0014.
Covers both activities (act1 with 2 blocks, act2 with 1 block).
Range: from first 0x1f request to final 0x20 ACK.
"""

import subprocess
import sys

LOG = "/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log"

# BLE ATT opcodes
ATT_OPCODES = {
    '0x01': 'ATT_ERROR_RSP',
    '0x02': 'ATT_EXCHANGE_MTU_REQ',
    '0x03': 'ATT_EXCHANGE_MTU_RSP',
    '0x08': 'ATT_READ_BY_TYPE_REQ',
    '0x09': 'ATT_READ_BY_TYPE_RSP',  # also 0x09 in app protocol = DATA_READY
    '0x0a': 'ATT_READ_REQ',
    '0x0b': 'ATT_READ_RSP',
    '0x0c': 'ATT_READ_BLOB_REQ',
    '0x0d': 'ATT_READ_BLOB_RSP',
    '0x12': 'ATT_WRITE_REQ',        # phone→watch
    '0x13': 'ATT_WRITE_RSP',        # watch→phone (ACK of write)
    '0x1b': 'ATT_HANDLE_VALUE_NTF', # watch→phone (notification)
    '0x1d': 'ATT_HANDLE_VALUE_IND', # watch→phone (indication)
    '0x1e': 'ATT_HANDLE_VALUE_CFM', # phone→watch (confirm indication)
    '0x52': 'ATT_WRITE_CMD',        # phone→watch (no response)
}

# App-level protocol bytes for h0011 (first byte of value)
APP_PROTOCOL = {
    '00': 'BLOCK_REQUEST (phone→watch)',
    '04': 'BLOCK_ACK / CONFIRM (phone→watch)',
    '07': 'BLOCK_DONE (watch→phone)',
    '09': 'DATA_READY (watch→phone)',
    '1f': 'TRACK_REQUEST cmd',
    '20': 'TRACK_ACK / END cmd',
    '1d': 'ACTIVITY_REQUEST cmd',
    '1e': 'ACTIVITY_DATA',
}

def get_direction(opcode_str):
    """Determine direction based on ATT opcode."""
    # phone→watch: WRITE_REQ(0x12), WRITE_CMD(0x52), HANDLE_VALUE_CFM(0x1e)
    # watch→phone: NTF(0x1b), IND(0x1d), WRITE_RSP(0x13)
    phone_to_watch = {'0x12', '0x52', '0x1e', '0x02', '0x08', '0x0a', '0x0c'}
    watch_to_phone = {'0x1b', '0x1d', '0x13', '0x03', '0x09', '0x0b', '0x0d'}
    if opcode_str in phone_to_watch:
        return 'Phone→Watch'
    elif opcode_str in watch_to_phone:
        return 'Watch→Phone'
    return '???'

def interpret_value(handle, opcode, value_hex):
    """Interpret the value bytes based on handle and opcode."""
    if not value_hex:
        return '(empty - ACK/RSP)'

    val = value_hex.strip()
    if not val:
        return '(empty - ACK/RSP)'

    # Parse bytes
    try:
        b = bytes.fromhex(val)
    except ValueError:
        return f'(parse error: {val})'

    if handle == '0x0011':
        if len(b) == 0:
            return '(empty)'
        first = format(b[0], '02x')

        if opcode in ('0x12', '0x52'):  # phone→watch write
            if first == '00':
                # BLOCK_REQUEST: 00 XX 00 addr(4LE) 00 len(4LE)?
                # format: 00 cmd_id 00 block_addr(4LE) flags(1) block_len(4LE)
                # Actually from examples: 001d00a0460000010000
                # 00 1d 00 a0460000 01 0000
                if len(b) >= 2:
                    cmd_id = format(b[1], '02x')
                    rest = val[4:] if len(val) > 4 else ''
                    if len(b) >= 6:
                        addr = int.from_bytes(b[3:7], 'little') if len(b) >= 7 else 0
                        return f'BLOCK_REQ cmd=0x{cmd_id} addr=0x{addr:08x} rest={val[2:]}'
                    return f'BLOCK_REQ cmd=0x{cmd_id} data={val[2:]}'
            elif first == '04':
                cmd_id = format(b[1], '02x') if len(b) > 1 else '?'
                return f'BLOCK_ACK/CONFIRM cmd=0x{cmd_id} data={val[2:]}'
            elif first == '09':
                cmd_id = format(b[1], '02x') if len(b) > 1 else '?'
                return f'DATA_READY_ACK cmd=0x{cmd_id} data={val[2:]}'
            elif first == '1f':
                if len(b) >= 4:
                    addr = int.from_bytes(b[2:6], 'little') if len(b) >= 6 else 0
                    return f'TRACK_DATA_REQUEST addr=0x{int.from_bytes(b[2:6], "little"):08x} data={val[4:]}'
                return f'TRACK_DATA_REQUEST data={val[2:]}'
            elif first == '20':
                return f'TRACK_END/ACK data={val[2:]}'
            else:
                return f'h0011 WRITE first=0x{first} data={val}'

        elif opcode in ('0x1b', '0x1d'):  # watch→phone notification/indication
            if first == '00':
                cmd_id = format(b[1], '02x') if len(b) > 1 else '?'
                if len(b) >= 6:
                    addr = int.from_bytes(b[3:7], 'little') if len(b) >= 7 else 0
                    return f'ECHO BLOCK_REQ cmd=0x{cmd_id} addr=0x{int.from_bytes(b[3:7], "little"):08x} data={val[4:]}'
                return f'ECHO/BLOCK_RESP cmd=0x{cmd_id} data={val[2:]}'
            elif first == '07':
                cmd_id = format(b[1], '02x') if len(b) > 1 else '?'
                return f'BLOCK_DONE cmd=0x{cmd_id} data={val[2:]}'
            elif first == '09':
                cmd_id = format(b[1], '02x') if len(b) > 1 else '?'
                return f'DATA_READY cmd=0x{cmd_id} data={val[2:]}'
            elif first == '04':
                cmd_id = format(b[1], '02x') if len(b) > 1 else '?'
                return f'ACK/CONFIRM cmd=0x{cmd_id} data={val[2:]}'
            else:
                return f'h0011 NTF first=0x{first} data={val}'

        elif opcode == '0x13':  # write RSP (watch→phone, empty ACK)
            return '(WRITE_RSP - ACK of write)'

    elif handle == '0x0014':
        if opcode in ('0x52', '0x12'):  # phone→watch
            if len(b) >= 1:
                first = format(b[0], '02x')
                if first == '04' and len(b) >= 2:
                    sub = format(b[1], '02x')
                    return f'h0014 WRITE cmd=0x{first}{sub} data={val[4:] if len(val)>4 else ""}'
                elif first == '06':
                    return f'h0014 WRITE SYNC/CTL data={val[2:]}'
                elif first == '07':
                    return f'h0014 WRITE TRANSFER_CTL data={val[2:]}'
                return f'h0014 WRITE first=0x{first} data={val}'
        elif opcode in ('0x1b',):  # notification watch→phone
            if len(b) >= 1:
                first = format(b[0], '02x')
                if first == '05':
                    return f'CONVOY_DATA ({len(b)} bytes, data[0:8]={val[2:18]}...)'
                elif first == '04':
                    return f'h0014 NTF CTL data={val[2:]}'
                elif first == '06':
                    return f'h0014 NTF SYNC data={val[2:]}'
                elif first == '07':
                    return f'h0014 NTF TRANSFER_CTL data={val[2:]}'
                return f'h0014 NTF first=0x{first} data={val}'
        elif opcode == '0x13':
            return '(WRITE_RSP)'

    return f'val={val}'

# Get all frames on h0011 and h0014
cmd = [
    "tshark", "-r", LOG,
    "-Y", "btatt and (btatt.handle == 0x0011 or btatt.handle == 0x0014)",
    "-T", "fields",
    "-e", "frame.number",
    "-e", "frame.time_relative",
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
frames = []
for line in lines:
    if not line.strip():
        continue
    parts = line.split('|')
    if len(parts) < 5:
        continue
    frames.append({
        'num': int(parts[0].strip()),
        'time': parts[1].strip(),
        'opcode': parts[2].strip(),
        'handle': parts[3].strip(),
        'value': parts[4].strip(),
    })

print(f"Total frames on h0011/h0014: {len(frames)}")
print()

# Find the range for track operations
# Look for first 0x1f command and last 0x20 command
first_1f = None
last_20 = None

for f in frames:
    val = f['value']
    h = f['handle']
    op = f['opcode']

    # Find track requests (0x1f) - written to h0011
    if h == '0x0011' and op in ('0x12', '0x52') and val.startswith('1f'):
        if first_1f is None:
            first_1f = f['num']

    # Find 0x20 ACK/end
    if h == '0x0011' and op in ('0x12', '0x52') and val.startswith('20'):
        last_20 = f['num']

# Also look at echoes and NTFs for 1f/20
for f in frames:
    val = f['value']
    h = f['handle']
    op = f['opcode']
    if h == '0x0011' and val.startswith('1f') and first_1f is None:
        first_1f = f['num']
    if h == '0x0011' and val.startswith('20'):
        if last_20 is None or f['num'] > last_20:
            last_20 = f['num']

print(f"First 0x1f frame: #{first_1f}")
print(f"Last 0x20 frame: #{last_20}")
print()

# Show all 1f and 20 frames
print("=== All 0x1f and 0x20 frames ===")
for f in frames:
    val = f['value']
    h = f['handle']
    op = f['opcode']
    if h == '0x0011' and (val.startswith('1f') or val.startswith('20')):
        direction = get_direction(op)
        interp = interpret_value(h, op, val)
        att_name = ATT_OPCODES.get(op, op)
        print(f"  Frame #{f['num']:5d} t={f['time']:16s} {direction:14s} {h} {att_name:25s} | {val[:60]}")
        print(f"         -> {interp}")

print()

# Show ALL 0x07 BLOCK_DONE frames on h0011
print("=== All 0x07 BLOCK_DONE frames on h0011 ===")
for f in frames:
    val = f['value']
    h = f['handle']
    op = f['opcode']
    if h == '0x0011' and val.startswith('07'):
        direction = get_direction(op)
        interp = interpret_value(h, op, val)
        att_name = ATT_OPCODES.get(op, op)
        print(f"  Frame #{f['num']:5d} t={f['time']:16s} {direction:14s} {h} {att_name:25s} | {val}")
        print(f"         -> {interp}")

print()

# Now filter to the range first_1f-100 to last_20+20 to find all track frames
if first_1f is None:
    print("ERROR: Could not find first 0x1f frame!")
    sys.exit(1)

# Extend range slightly before first_1f to capture lead-up
range_start = first_1f - 20
range_end = last_20 + 30 if last_20 else frames[-1]['num']

track_frames = [f for f in frames if range_start <= f['num'] <= range_end]

print(f"=== FULL CHRONOLOGICAL TABLE: Frames #{range_start} to #{range_end} ===")
print(f"{'Frame':>6} {'Time':>16} {'Dir':>14} {'Handle':>8} {'ATT Op':>25} | Value (truncated to 60) | Interpretation")
print("-" * 160)

for f in track_frames:
    h = f['handle']
    op = f['opcode']
    val = f['value']
    direction = get_direction(op)
    interp = interpret_value(h, op, val)
    att_name = ATT_OPCODES.get(op, op)
    val_display = val[:80] + ('...' if len(val) > 80 else '')
    print(f"  {f['num']:5d} {f['time']:>16s} {direction:>14s} {h:>8s} {att_name:>25s} | {val_display}")
    print(f"         -> {interp}")
    print()
