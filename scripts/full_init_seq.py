#!/usr/bin/env python3
"""
Full detailed dump of ALL ATT operations around the Casio init sequences
found in the CFA.curf file.  Shows CCC subscriptions, time writes,
config writes (0x45/0x43/0x13), and everything in between.
"""
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "logs_5/BT_HCI_2026_0430_170304_UTC+0200.cfa.curf"
START = int(sys.argv[2]) if len(sys.argv) > 2 else 0
END   = int(sys.argv[3]) if len(sys.argv) > 3 else 999999

FEAT = {
    0x09: 'TIME', 0x10: 'BLE_FEAT', 0x11: 'BLE_SET',
    0x13: 'BASIC', 0x1d: 'DST_WATCH', 0x1e: 'DST_SET',
    0x1f: 'WORLD_CITY', 0x20: 'VER_INFO', 0x22: 'APP_INFO',
    0x23: 'WATCH_NAME', 0x26: 'MODULE_ID', 0x28: 'WATCH_COND',
    0x3a: 'CONN_PARAM', 0x3b: 'ADV_PARAM', 0x3d: 'BLE_PARAM',
    0x43: 'TARGET_VAL', 0x45: 'USER_PROF', 0x47: 'SVC_DISC',
    0x39: 'TIME_REQ',
}

ATT_OPS = {
    0x01: 'ERR_RSP', 0x02: 'MTU_REQ', 0x03: 'MTU_RSP',
    0x04: 'FIND_INFO_REQ', 0x05: 'FIND_INFO_RSP',
    0x08: 'RBT_REQ', 0x09: 'RBT_RSP',
    0x0a: 'READ_REQ', 0x0b: 'READ_RSP',
    0x10: 'RBG_REQ', 0x11: 'RBG_RSP',
    0x12: 'WRITE_REQ', 0x13: 'WRITE_RSP',
    0x52: 'WRITE_CMD', 0x1b: 'NTF',
}

def xd(b, n=40):
    s = ' '.join(f'{x:02x}' for x in b[:n])
    return s + ('...' if len(b) > n else '')

reassembly = {}

def show(pkt_num, direction, op, h, val):
    dir_s = '→W' if direction == 0 else '←W'
    op_name = ATT_OPS.get(op, f'0x{op:02x}')
    f0 = val[0] if val else 0
    fname = FEAT.get(f0, f'0x{f0:02x}')
    if op in (0x12, 0x52, 0x1b):
        # Highlight config features
        mark = '***' if f0 in (0x45, 0x43, 0x13, 0x09, 0x39) else '   '
        print(f'{mark}[{pkt_num:6d}] {dir_s} {op_name:10s} h{h:04x}  {fname:14s}  {xd(val)}')
    elif op in (0x02, 0x03):
        mtu = struct.unpack('<H', val)[0] if len(val) >= 2 else 0
        print(f'   [{pkt_num:6d}] {dir_s} {op_name:10s} mtu={mtu}')
    elif h is not None:
        # CCC subscriptions or other writes
        if len(val) == 2:
            ccc = struct.unpack('<H', val)[0]
            print(f'   [{pkt_num:6d}] {dir_s} {op_name:10s} h{h:04x}  CCC={ccc:#06x}')
        else:
            print(f'   [{pkt_num:6d}] {dir_s} {op_name:10s} h{h:04x}  {xd(val)}')
    else:
        print(f'   [{pkt_num:6d}] {dir_s} {op_name:10s} {xd(val)}')

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

        if pkt_num < START or pkt_num > END:
            continue
        if not data or data[0] != 0x02:
            continue
        if len(data) < 5:
            continue

        hw = struct.unpack('<H', data[1:3])[0]
        conn_h = hw & 0x0fff
        pb = (hw >> 12) & 0x03
        payload = data[5:]

        if conn_h != 0x0200:
            continue

        if pb in (0x00, 0x02):
            if len(payload) < 4:
                continue
            l2_len = struct.unpack('<H', payload[0:2])[0]
            cid = struct.unpack('<H', payload[2:4])[0]
            if cid != 0x0004:
                continue
            att_data = payload[4:]
            if len(att_data) < l2_len:
                reassembly[conn_h] = (bytearray(att_data), l2_len, pkt_num, direction)
                continue
            att = bytes(att_data[:l2_len])
        elif pb == 0x01:
            if conn_h not in reassembly:
                continue
            buf, expected, pkt_s, dir0 = reassembly[conn_h]
            buf.extend(payload)
            if len(buf) < expected:
                reassembly[conn_h] = (buf, expected, pkt_s, dir0)
                continue
            att = bytes(buf[:expected])
            direction = dir0
            del reassembly[conn_h]
        else:
            continue

        if not att:
            continue
        op = att[0]

        if op in (0x02, 0x03):
            mtu_val = att[1:3]
            show(pkt_num, direction, op, None, mtu_val)
        elif op in (0x12, 0x52, 0x1b):
            if len(att) < 3:
                continue
            h = struct.unpack('<H', att[1:3])[0]
            val = att[3:]
            show(pkt_num, direction, op, h, val)
        elif op == 0x13:
            pass  # WRITE_RSP silent
