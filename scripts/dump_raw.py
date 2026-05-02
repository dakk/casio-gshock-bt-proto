#!/usr/bin/env python3
"""Raw dump of all HCI packets to understand the log structure."""
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "btsnoop_hci_5.log"
MAX = int(sys.argv[2]) if len(sys.argv) > 2 else 200

def xd(b, n=20):
    return ' '.join(f'{x:02x}' for x in b[:n]) + ('...' if len(b) > n else '')

with open(LOG, 'rb') as f:
    hdr = f.read(16)
    print(f"Magic: {hdr[:8]}  version={struct.unpack('>I', hdr[8:12])[0]}  datalink={struct.unpack('>I', hdr[12:16])[0]}")

    pkt_num = 0
    while pkt_num < MAX:
        rec_hdr = f.read(24)
        if len(rec_hdr) < 24:
            break
        orig_len, incl_len, flags, drops, ts = struct.unpack('>IIIIQ', rec_hdr)
        data = f.read(incl_len)
        direction = flags & 1
        dir_s = '→' if direction == 0 else '←'
        pkt_type = data[0] if data else 0xff
        type_name = {0x01: 'CMD', 0x02: 'ACL', 0x03: 'SCO', 0x04: 'EVT'}.get(pkt_type, f'0x{pkt_type:02x}')
        print(f"[{pkt_num:4d}] {dir_s} flags={flags:#06x} type={type_name:4s} len={incl_len:4d}  {xd(data)}")
        pkt_num += 1
