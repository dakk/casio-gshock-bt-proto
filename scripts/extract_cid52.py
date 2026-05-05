#!/usr/bin/env python3
"""Extract L2CAP CID 0x0052 packets and analyze sport activity data."""
import struct, sys

LOG       = sys.argv[1] if len(sys.argv) > 1 else "dumps/logs_9/btsnoop_hci.log.last"
TARGET_CONN = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x0033
TARGET_CID  = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x0052
LIMIT       = int(sys.argv[4]) if len(sys.argv) > 4 else 80

def xd(b, n=48):
    s = ' '.join(f'{x:02x}' for b2 in [b[:n]] for x in b2)
    return s + ('...' if len(b) > n else '')

with open(LOG, 'rb') as f:
    f.read(16)
    pkt_num = 0
    shown   = 0
    reassembly = {}   # conn_h -> (cid, buf, expected)

    while shown < LIMIT:
        rec_hdr = f.read(24)
        if len(rec_hdr) < 24:
            break
        orig_len, incl_len, flags, drops, ts = struct.unpack('>IIIIQ', rec_hdr)
        data = f.read(incl_len)
        direction = flags & 1
        pkt_num += 1

        if not data or data[0] != 0x02 or len(data) < 9:
            continue

        handle_word = struct.unpack('<H', data[1:3])[0]
        conn_h = handle_word & 0x0fff
        pb     = (handle_word >> 12) & 0x03

        if conn_h != TARGET_CONN:
            continue

        if pb in (0x00, 0x02):
            l2_payload = data[5:]
            if len(l2_payload) < 4:
                continue
            l2_len = struct.unpack('<H', l2_payload[0:2])[0]
            cid    = struct.unpack('<H', l2_payload[2:4])[0]
            if cid != TARGET_CID:
                continue
            payload = bytearray(l2_payload[4:])
            if len(payload) < l2_len:
                reassembly[conn_h] = (cid, payload, l2_len)
            else:
                dir_s = '→W' if direction == 0 else '←W'
                print(f"[{pkt_num:5d}] {dir_s} l2={l2_len:4d}  {xd(bytes(payload[:l2_len]))}")
                shown += 1
        elif pb == 0x01:
            if conn_h in reassembly:
                cid2, buf, expected = reassembly[conn_h]
                buf.extend(data[5:])
                if len(buf) >= expected:
                    if cid2 == TARGET_CID:
                        dir_s = '→W' if direction == 0 else '←W'
                        print(f"[{pkt_num:5d}] {dir_s} l2={expected:4d}  [reassembled]  {xd(bytes(buf[:expected]))}")
                        shown += 1
                    del reassembly[conn_h]
