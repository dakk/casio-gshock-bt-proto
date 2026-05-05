#!/usr/bin/env python3
"""Analyze L2CAP CID 0x0052 LECOC channel structure and try to find Casio sport data."""
import struct, sys, collections

LOG       = sys.argv[1] if len(sys.argv) > 1 else "dumps/logs_9/btsnoop_hci.log.last"
TARGET_CONN = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x0033
TARGET_CID  = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x0052

def xd(b, n=32):
    s = ' '.join(f'{x:02x}' for x in b[:n])
    return s + ('...' if len(b) > n else '')

stats = {'sent': 0, 'recv': 0, 'sent_bytes': 0, 'recv_bytes': 0}
all_pkts = []

with open(LOG, 'rb') as f:
    f.read(16)
    pkt_num = 0
    reassembly = {}

    while True:
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
                reassembly[conn_h] = (cid, payload, l2_len, direction, pkt_num)
            else:
                all_pkts.append((pkt_num, direction, bytes(payload[:l2_len])))
        elif pb == 0x01:
            if conn_h in reassembly:
                cid2, buf, expected, direction2, pkt_num2 = reassembly[conn_h]
                buf.extend(data[5:])
                if len(buf) >= expected:
                    if cid2 == TARGET_CID:
                        all_pkts.append((pkt_num2, direction2, bytes(buf[:expected])))
                    del reassembly[conn_h]

print(f"Total packets on CID 0x{TARGET_CID:04x}: {len(all_pkts)}")
for pn, d, p in all_pkts:
    if d == 0:
        stats['sent'] += 1; stats['sent_bytes'] += len(p)
    else:
        stats['recv'] += 1; stats['recv_bytes'] += len(p)

print(f"  Phone→Watch (dir=0): {stats['sent']:5d} pkts  {stats['sent_bytes']:8d} bytes")
print(f"  Watch→Phone (dir=1): {stats['recv']:5d} pkts  {stats['recv_bytes']:8d} bytes")

# Show first bytes of each direction
print("\n--- First 10 Phone→Watch packets (first 32 bytes) ---")
count = 0
for pn, d, p in all_pkts:
    if d == 0:
        print(f"  [{pn:5d}] len={len(p):4d}  {xd(p)}")
        count += 1
        if count >= 10:
            break

print("\n--- First 10 Watch→Phone packets (first 32 bytes) ---")
count = 0
for pn, d, p in all_pkts:
    if d == 1:
        print(f"  [{pn:5d}] len={len(p):4d}  {xd(p)}")
        count += 1
        if count >= 10:
            break

# Analyze header bytes [0:8] for patterns
print("\n--- Byte frequency analysis (first 8 bytes, Phone→Watch) ---")
freq = [collections.Counter() for _ in range(8)]
for pn, d, p in all_pkts:
    if d == 0:
        for i in range(min(8, len(p))):
            freq[i][p[i]] += 1
for i in range(8):
    top = freq[i].most_common(5)
    topstr = ', '.join(f'0x{v:02x}({c})' for v, c in top)
    print(f"  byte[{i}]: {topstr}")

# Check XOR decode patterns: does XOR with 0xFF reveal meaningful data?
print("\n--- First Watch→Phone packet XOR decoded ---")
count = 0
for pn, d, p in all_pkts:
    if d == 1:
        xord = bytes(b ^ 0xff for b in p)
        print(f"  raw:  {xd(p)}")
        print(f"  xord: {xd(xord)}")
        count += 1
        if count >= 3:
            break
