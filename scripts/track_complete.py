#!/usr/bin/env python3
"""
Complete chronological table of all track-related frames.
Range: frame 4859 (first 001f request) through frame 5786 (post-0x20 cleanup).
"""

import subprocess
import sys

LOG = "/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log"

ATT_OPCODES = {
    '0x12': 'WRITE_REQ',
    '0x13': 'WRITE_RSP',
    '0x1b': 'HANDLE_NTF',
    '0x1d': 'HANDLE_IND',
    '0x1e': 'HANDLE_CFM',
    '0x52': 'WRITE_CMD',
}

def direction(opcode):
    p2w = {'0x12', '0x52', '0x1e'}
    w2p = {'0x1b', '0x1d', '0x13'}
    if opcode in p2w: return 'Ph→Wa'
    if opcode in w2p: return 'Wa→Ph'
    return '?????'

def decode_h0011(val, opcode):
    """Decode h0011 value."""
    if not val:
        return '(empty WRITE_RSP)'
    try:
        b = bytes.fromhex(val)
    except:
        return f'[parse err: {val}]'

    first = b[0]
    second = b[1] if len(b) > 1 else None

    if opcode in ('0x12', '0x52'):
        # Phone → Watch
        if first == 0x00 and second is not None:
            cmd = b[1]
            # format: 00 cmd 00 addr[4LE] flags[1] extra[2]
            if len(b) >= 7:
                addr = int.from_bytes(b[3:7], 'little')
                flags = b[7] if len(b) > 7 else 0
                extra = val[16:] if len(val) > 16 else ''
                return f'BLOCK_REQ cmd=0x{cmd:02x} addr=0x{addr:08x} flags=0x{flags:02x} extra={extra}'
            elif len(b) >= 2:
                return f'BLOCK_REQ cmd=0x{cmd:02x} data={val[2:]}'
        elif first == 0x04:
            cmd = b[1] if len(b) > 1 else 0
            return f'BLOCK_ACK cmd=0x{cmd:02x} data={val[4:] if len(val)>4 else ""}'
        elif first == 0x09:
            cmd = b[1] if len(b) > 1 else 0
            return f'DATA_READY_ACK cmd=0x{cmd:02x}'
        elif first == 0x07:
            cmd = b[1] if len(b) > 1 else 0
            return f'[ECHO] BLOCK_DONE cmd=0x{cmd:02x}'
        return f'WRITE first=0x{first:02x} data={val}'

    elif opcode in ('0x1b', '0x1d'):
        # Watch → Phone
        if first == 0x00 and second is not None:
            cmd = b[1]
            if len(b) >= 7:
                addr = int.from_bytes(b[3:7], 'little')
                return f'[ECHO] BLOCK_REQ cmd=0x{cmd:02x} addr=0x{addr:08x}'
            return f'[ECHO] BLOCK_REQ cmd=0x{cmd:02x} data={val[2:]}'
        elif first == 0x07:
            cmd = b[1] if len(b) > 1 else 0
            return f'BLOCK_DONE cmd=0x{cmd:02x}'
        elif first == 0x09:
            cmd = b[1] if len(b) > 1 else 0
            return f'DATA_READY cmd=0x{cmd:02x}'
        elif first == 0x04:
            cmd = b[1] if len(b) > 1 else 0
            return f'[NTF] ACK cmd=0x{cmd:02x}'
        return f'NTF first=0x{first:02x} data={val}'

    elif opcode == '0x13':
        return '(WRITE_RSP ack)'
    return f'op={opcode} data={val}'

def decode_h0014(val, opcode):
    if not val:
        return '(empty)'
    try:
        b = bytes.fromhex(val)
    except:
        return f'[parse err: {val}]'
    first = b[0]
    if opcode in ('0x52', '0x12'):
        # Phone → Watch
        sub = f'{b[1]:02x}' if len(b) > 1 else ''
        rest = val[4:] if len(val) > 4 else ''
        return f'Ph→Wa cmd=0x{first:02x}{sub} data={rest[:40]}'
    elif opcode == '0x1b':
        # Watch → Phone notification
        if first == 0x05:
            return f'CONVOY_DATA ({len(b)} bytes)'
        sub = f'{b[1]:02x}' if len(b) > 1 else ''
        return f'Wa→Ph cmd=0x{first:02x}{sub} data={val[4:20]}...'
    elif opcode == '0x13':
        return '(WRITE_RSP)'
    return f'op={opcode} data={val[:40]}'

# Get all frames in range
cmd = [
    "tshark", "-r", LOG,
    "-Y", f"btatt and (btatt.handle == 0x0011 or btatt.handle == 0x0014) and frame.number >= 4840 and frame.number <= 5790",
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
    print("Error:", result.stderr)
    sys.exit(1)

frames = []
for line in result.stdout.strip().split('\n'):
    if not line.strip(): continue
    p = line.split('|')
    if len(p) < 5: continue
    frames.append({
        'num': int(p[0].strip()),
        'time': p[1].strip(),
        'opcode': p[2].strip(),
        'handle': p[3].strip(),
        'value': p[4].strip(),
    })

# Identify block/activity boundaries
# From the data seen:
# act1: frames around 4859-5409 (0x1f blocks)
# act2: frames around 5413-5770 (0x1f and 0x20 blocks)

print("=" * 130)
print(f"{'Frame':>6} {'Time(s)':>14} {'Dir':>5} {'Handle':>6} {'ATT Op':>10} | {'Value (hex, truncated)':45} | Interpretation")
print("=" * 130)

# Track state for annotations
current_activity = None
current_block_cmd = None
events = []

for f in frames:
    num = f['num']
    t = f['time']
    op = f['opcode']
    h = f['handle']
    val = f['value']
    dir_ = direction(op)
    att = ATT_OPCODES.get(op, op)

    if h == '0x0011':
        dec = decode_h0011(val, op)
    else:
        dec = decode_h0014(val, op)

    val_disp = val[:90] + ('...' if len(val) > 90 else '')

    # Annotations
    note = ''
    if h == '0x0011' and val:
        try:
            b = bytes.fromhex(val)
            first = b[0] if b else 0
            second = b[1] if len(b) > 1 else 0

            if op in ('0x12', '0x52'):
                if first == 0x00:  # BLOCK_REQUEST
                    cmd_id = second
                    if cmd_id == 0x1f:
                        note = f'*** TRACK_BLOCK_REQ (act1/2 block)'
                    elif cmd_id == 0x20:
                        note = f'*** FINAL_BLOCK_REQ (0x20 block)'
                elif first == 0x04:
                    cmd_id = second
                    if cmd_id == 0x1f:
                        note = '*** ACK for 0x1f block'
                    elif cmd_id == 0x20:
                        note = '*** ACK for 0x20 block (FINAL ACK!)'
                    elif cmd_id == 0x07:
                        note = '   echo BLOCK_DONE back to watch'
                elif first == 0x07:
                    note = '   [echo BLOCK_DONE to watch]'

            elif op in ('0x1b', '0x1d'):
                if first == 0x07:
                    cmd_id = second
                    if cmd_id == 0x1f:
                        note = '*** WATCH: BLOCK_DONE for 0x1f'
                    elif cmd_id == 0x20:
                        note = '*** WATCH: BLOCK_DONE for 0x20 (FINAL!)'
                elif first == 0x09:
                    cmd_id = second
                    note = f'*** WATCH: DATA_READY cmd=0x{cmd_id:02x}'
                elif first == 0x00:
                    cmd_id = second
                    note = f'   watch echoes BLOCK_REQ cmd=0x{cmd_id:02x}'
        except:
            pass

    print(f"  {num:5d} {t:>14s} {dir_:>5s} {h:>6s} {att:>10s} | {val_disp:90s} | {dec}")
    if note:
        print(f"        *** NOTE: {note}")

print()
print("=" * 130)
print()

# Summary analysis
print("SUMMARY ANALYSIS")
print("=" * 80)

# Find all key events
block_reqs = []
block_done = []
block_ack = []
data_ready = []
convoy_pkts = {}

for f in frames:
    num = f['num']
    val = f['value']
    op = f['opcode']
    h = f['handle']
    if not val: continue
    try:
        b = bytes.fromhex(val)
    except:
        continue

    if h == '0x0011':
        first = b[0] if b else 0
        second = b[1] if len(b) > 1 else 0

        if op in ('0x12', '0x52') and first == 0x00:
            cmd = second
            addr = int.from_bytes(b[3:7], 'little') if len(b) >= 7 else 0
            block_reqs.append((num, f['time'], cmd, addr, val))

        elif op in ('0x1b', '0x1d') and first == 0x07:
            cmd = second
            block_done.append((num, f['time'], cmd, val))

        elif op in ('0x12', '0x52') and first == 0x04:
            cmd = second
            block_ack.append((num, f['time'], cmd, val))

        elif op in ('0x1b',) and first == 0x09:
            cmd = second
            data_ready.append((num, f['time'], cmd, val))

    elif h == '0x0014' and op == '0x1b':
        first = b[0] if b else 0
        if first == 0x05:
            convoy_pkts[num] = len(b)

print()
print("BLOCK REQUESTS (phone→watch, 00 cmd addr...):")
for req in block_reqs:
    num, t, cmd, addr, val = req
    print(f"  Frame #{num:5d} t={t:12s} cmd=0x{cmd:02x} addr=0x{addr:08x} | {val}")

print()
print("BLOCK_DONE notifications (watch→phone, 07 cmd ...):")
for bd in block_done:
    num, t, cmd, val = bd
    print(f"  Frame #{num:5d} t={t:12s} cmd=0x{cmd:02x} | {val}")

print()
print("BLOCK ACKs (phone→watch, 04 cmd ...):")
for ba in block_ack:
    num, t, cmd, val = ba
    print(f"  Frame #{num:5d} t={t:12s} cmd=0x{cmd:02x} | {val}")

print()
print("DATA_READY (watch→phone, 09 cmd ...):")
for dr in data_ready:
    num, t, cmd, val = dr
    print(f"  Frame #{num:5d} t={t:12s} cmd=0x{cmd:02x} | {val}")

print()
print(f"Total CONVOY_DATA packets (h0014 0x05...): {len(convoy_pkts)}")

print()
print("SEQUENCE RECONSTRUCTION:")
print("-" * 60)
print("Act1 block 1 (cmd=0x1f):")
print("  Phone sends: 00 1f ... BLOCK_REQ")
print("  Watch echoes: 00 1f ...")
print("  [convoy data packets on h0014]")
print("  Watch sends: 07 1f ... BLOCK_DONE")
print("  Phone echoes BLOCK_DONE: 07 1f ...")
print("  [write_rsp]")
print("  Phone sends: ? (04 1f? or next 00 1f?)")
