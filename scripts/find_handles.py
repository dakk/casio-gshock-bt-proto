#!/usr/bin/env python3
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "btsnoop_hci_5.log"
handle_ops = {}
samples = {}

with open(LOG, 'rb') as f:
    hdr = f.read(16)
    while True:
        rec_hdr = f.read(24)
        if len(rec_hdr) < 24:
            break
        orig_len, incl_len, flags, drops, ts = struct.unpack('>IIIIQ', rec_hdr)
        data = f.read(incl_len)
        direction = flags & 1
        if not data:
            continue
        if data[0] != 0x02:
            continue
        if len(data) < 9:
            continue
        l2 = data[5:]
        if len(l2) < 4:
            continue
        cid = struct.unpack('<H', l2[2:4])[0]
        if cid != 0x0004:
            continue
        att = l2[4:]
        if not att:
            continue
        op = att[0]
        if op in (0x12, 0x52, 0x1b) and len(att) >= 3:
            h = struct.unpack('<H', att[1:3])[0]
            val = att[3:]
            key = (h, op, direction)
            handle_ops[key] = handle_ops.get(key, 0) + 1
            if key not in samples:
                samples[key] = val[:16]

print(f"{'Handle':8s} {'Op':12s} {'Dir':8s} {'Count':6s}  Sample")
for (h, op, d), cnt in sorted(handle_ops.items()):
    op_name = {0x12: 'WRITE_REQ', 0x52: 'WRITE_CMD', 0x1b: 'NTF'}.get(op, f'0x{op:02x}')
    dir_s = '→WATCH' if d == 0 else '←WATCH'
    samp = ' '.join(f'{x:02x}' for x in samples.get((h, op, d), b''))
    print(f"  h{h:04x}  {op_name:12s}  {dir_s:8s}  {cnt:4d}  {samp}")
