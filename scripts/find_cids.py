#!/usr/bin/env python3
"""Find all L2CAP CIDs and all ATT operations regardless of CID."""
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "btsnoop_hci_5.log"
TARGET_HANDLE = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x0200

FEAT = {
    0x09: 'TIME', 0x10: 'BLE_FEAT', 0x11: 'BLE_SET',
    0x13: 'BASIC', 0x1d: 'DST_WATCH', 0x1e: 'DST_SET',
    0x1f: 'WORLD_CITY', 0x20: 'VER_INFO', 0x22: 'APP_INFO',
    0x23: 'WATCH_NAME', 0x26: 'MODULE_ID', 0x28: 'WATCH_COND',
    0x3a: 'CONN_PARAM', 0x3b: 'ADV_PARAM', 0x3d: 'RECONNECT',
    0x43: 'TARGET_VAL', 0x45: 'USER_PROF', 0x47: 'SVC_DISC',
}

ATT_OPS = {
    0x01: 'ERR_RSP', 0x02: 'MTU_REQ', 0x03: 'MTU_RSP',
    0x04: 'FIND_INFO_REQ', 0x05: 'FIND_INFO_RSP',
    0x08: 'READ_BY_TYPE_REQ', 0x09: 'READ_BY_TYPE_RSP',
    0x0a: 'READ_REQ', 0x0b: 'READ_RSP',
    0x10: 'READ_BY_GRP_REQ', 0x11: 'READ_BY_GRP_RSP',
    0x12: 'WRITE_REQ', 0x13: 'WRITE_RSP',
    0x52: 'WRITE_CMD', 0x1b: 'NTF', 0x1d: 'IND', 0x1e: 'IND_CNF',
}

def xd(b, n=48):
    s = ' '.join(f'{x:02x}' for x in b[:n])
    return s + ('...' if len(b) > n else '')

cid_counts = {}
pkt_sizes = []
reassembly_buf = {}   # conn_handle -> (cid, accumulated_payload, expected_len)

def process_att(att, direction, pkt_num, cid):
    if not att:
        return
    op = att[0]
    op_name = ATT_OPS.get(op, f'op=0x{op:02x}')
    dir_s = '→W' if direction == 0 else '←W'
    if op in (0x12, 0x52, 0x1b, 0x1d):
        if len(att) < 3:
            return
        h = struct.unpack('<H', att[1:3])[0]
        val = att[3:]
        f = val[0] if val else 0
        fname = FEAT.get(f, f'0x{f:02x}')
        # For CCC writes (val = 0x0100 or 0x0000)
        if h > 0x0050 and len(val) == 2:
            ccc = struct.unpack('<H', val)[0]
            fname = f'CCC={ccc:#06x}'
        print(f'[{pkt_num:5d}] {dir_s} {op_name:10s} h{h:04x}  {fname:18s}  {xd(val,40)}')
    elif op in (0x02, 0x03):
        mtu = struct.unpack('<H', att[1:3])[0] if len(att) >= 3 else 0
        print(f'[{pkt_num:5d}] {dir_s} {op_name} mtu={mtu}')
    elif op == 0x10:
        s = struct.unpack('<H', att[1:3])[0] if len(att) >= 3 else 0
        e = struct.unpack('<H', att[3:5])[0] if len(att) >= 5 else 0
        print(f'[{pkt_num:5d}] {dir_s} {op_name} 0x{s:04x}-0x{e:04x}')
    elif op == 0x11:
        print(f'[{pkt_num:5d}] {dir_s} {op_name} {xd(att[1:])}')
    elif op == 0x08:
        s = struct.unpack('<H', att[1:3])[0] if len(att) >= 3 else 0
        e = struct.unpack('<H', att[3:5])[0] if len(att) >= 5 else 0
        print(f'[{pkt_num:5d}] {dir_s} {op_name} 0x{s:04x}-0x{e:04x}  {xd(att[5:])}')
    elif op == 0x09:
        print(f'[{pkt_num:5d}] {dir_s} {op_name} {xd(att[1:])}')
    elif op == 0x13:
        pass   # WRITE_RSP silent
    else:
        print(f'[{pkt_num:5d}] {dir_s} {op_name} {xd(att,48)}')

with open(LOG, 'rb') as f:
    f.read(16)
    pkt_num = 0
    while True:
        rec_hdr = f.read(24)
        if len(rec_hdr) < 24:
            break
        orig_len, incl_len, flags, drops, ts = struct.unpack('>IIIIQ', rec_hdr)
        data = f.read(incl_len)
        direction = flags & 1
        pkt_num += 1

        if not data or data[0] != 0x02:
            continue
        if len(data) < 5:
            continue

        handle_word = struct.unpack('<H', data[1:3])[0]
        conn_h = handle_word & 0x0fff
        pb = (handle_word >> 12) & 0x03
        total_len = struct.unpack('<H', data[3:5])[0]
        payload = data[5:]

        if conn_h != TARGET_HANDLE:
            continue

        if pb in (0x00, 0x02):  # Start of new packet
            if len(payload) < 4:
                continue
            l2_len = struct.unpack('<H', payload[0:2])[0]
            cid = struct.unpack('<H', payload[2:4])[0]
            cid_counts[cid] = cid_counts.get(cid, 0) + 1
            att_payload = payload[4:]

            if cid == 0x0004:  # ATT
                if len(att_payload) < l2_len:
                    # Fragmented — store in reassembly buffer
                    reassembly_buf[conn_h] = (cid, bytearray(att_payload), l2_len)
                else:
                    process_att(bytes(att_payload[:l2_len]), direction, pkt_num, cid)
        elif pb == 0x01:  # Continuation fragment
            if conn_h in reassembly_buf:
                cid, buf, expected = reassembly_buf[conn_h]
                buf.extend(payload)
                if len(buf) >= expected:
                    if cid == 0x0004:
                        process_att(bytes(buf[:expected]), direction, pkt_num, cid)
                    del reassembly_buf[conn_h]

print("\n--- L2CAP CIDs on this connection ---")
for cid, cnt in sorted(cid_counts.items()):
    names = {0x0004: 'ATT', 0x0005: 'L2CAP Signal', 0x0006: 'SMP'}
    n = names.get(cid, f'dyn=0x{cid:04x}')
    print(f"  CID=0x{cid:04x} ({n})  count={cnt}")
