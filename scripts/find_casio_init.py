#!/usr/bin/env python3
"""
Search ALL btsnoop logs for Casio initialization handshake.
Look for:
- ATT NTF or WRITE_CMD with value[0]=0x23 (WATCH_NAME), 0x22 (APP_INFO), 0x3d (RECONNECT)
- ATT NTF or WRITE_CMD to any handle with known Casio feature bytes
- Any handle that receives XOR'd data matching Casio patterns
"""
import struct, sys, os

FEAT = {
    0x09: 'TIME', 0x10: 'BLE_FEAT', 0x11: 'BLE_SET',
    0x13: 'BASIC', 0x1d: 'DST_WATCH', 0x1e: 'DST_SET',
    0x1f: 'WORLD_CITY', 0x20: 'VER_INFO', 0x22: 'APP_INFO',
    0x23: 'WATCH_NAME', 0x26: 'MODULE_ID', 0x28: 'WATCH_COND',
    0x3a: 'CONN_PARAM', 0x3b: 'ADV_PARAM', 0x3d: 'RECONNECT',
    0x43: 'TARGET_VAL', 0x45: 'USER_PROF', 0x47: 'SVC_DISC',
}

# Feature IDs we want to flag (init handshake)
INIT_FEATS = {0x23, 0x22, 0x10, 0x11, 0x3b, 0x3a, 0x26, 0x28, 0x20, 0x1d, 0x1e, 0x1f, 0x3d, 0x47}

ATT_OPS = {
    0x12: 'WRITE_REQ', 0x52: 'WRITE_CMD', 0x1b: 'NTF',
    0x02: 'MTU_REQ', 0x03: 'MTU_RSP',
    0x08: 'RBT_REQ', 0x09: 'RBT_RSP',
    0x10: 'RBG_REQ', 0x11: 'RBG_RSP',
    0x0a: 'READ_REQ', 0x0b: 'READ_RSP',
}

def xd(b, n=40):
    s = ' '.join(f'{x:02x}' for x in b[:n])
    return s + ('...' if len(b) > n else '')

def scan_file(path):
    reassembly = {}
    found_anything = False

    with open(path, 'rb') as f:
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

            hw = struct.unpack('<H', data[1:3])[0]
            conn_h = hw & 0x0fff
            pb = (hw >> 12) & 0x03
            payload = data[5:]

            if pb in (0x00, 0x02):
                if len(payload) < 4:
                    continue
                l2_len = struct.unpack('<H', payload[0:2])[0]
                cid = struct.unpack('<H', payload[2:4])[0]
                if cid != 0x0004:
                    continue
                att_data = payload[4:]
                if len(att_data) < l2_len:
                    reassembly[conn_h] = (cid, bytearray(att_data), l2_len, pkt_num, direction)
                    continue
                att = bytes(att_data[:l2_len])
            elif pb == 0x01:
                if conn_h not in reassembly:
                    continue
                cid, buf, expected, pkt_start, dir0 = reassembly[conn_h]
                buf.extend(payload)
                if len(buf) < expected:
                    reassembly[conn_h] = (cid, buf, expected, pkt_start, dir0)
                    continue
                att = bytes(buf[:expected])
                direction = dir0
                del reassembly[conn_h]
            else:
                continue

            if not att:
                continue

            op = att[0]
            dir_s = '→W' if direction == 0 else '←W'
            op_name = ATT_OPS.get(op, f'0x{op:02x}')

            # Check for MTU exchange (marks connection start)
            if op in (0x02, 0x03):
                mtu = struct.unpack('<H', att[1:3])[0] if len(att) >= 3 else 0
                print(f"  [{pkt_num:6d}] {dir_s} {op_name} mtu={mtu}  (conn_h=0x{conn_h:04x})")
                found_anything = True
                continue

            if op not in (0x12, 0x52, 0x1b):
                continue

            if len(att) < 3:
                continue
            h = struct.unpack('<H', att[1:3])[0]
            val = att[3:]
            if not val:
                continue

            f0 = val[0]
            fname = FEAT.get(f0, '')
            is_init = f0 in INIT_FEATS

            if is_init:
                print(f"  [{pkt_num:6d}] {dir_s} {op_name:10s} h{h:04x}  feat=0x{f0:02x}={fname:14s}  {xd(val)}")
                found_anything = True

    return found_anything

LOGS = [
    "btsnoop_hci_5.log",
    "logs_5/btsnoop_hci.log",
    "logs_5/btsnoop_hci.log.last",
    "logs_5/BT_HCI_2026_0430_154247_UTC+0200.cfa",
    "logs_5/BT_HCI_2026_0430_170304_UTC+0200.cfa.curf",
]

for log in LOGS:
    if not os.path.exists(log):
        print(f"\n=== {log} NOT FOUND ===")
        continue
    print(f"\n=== {log} ({os.path.getsize(log)//1024}KB) ===")
    found = scan_file(log)
    if not found:
        print("  (no Casio init features found)")
