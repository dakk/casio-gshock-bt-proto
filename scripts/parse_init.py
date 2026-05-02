#!/usr/bin/env python3
"""
Parse btsnoop HCI log and extract ATT WRITE/NOTIFY operations for Casio characteristics.
Focus on the initialization handshake.
"""
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "btsnoop_hci_5.log"

HANDLES = {
    0x0023: 'DATA_REQ_SP(h0011)',
    0x0024: 'CONVOY(h0014)',
    0x002c: 'ALL_REQ',
    0x002d: 'ALL_FEAT',
    0x0030: 'NOTIF',
    0x0025: 'h0011-CCC',
    0x0026: 'h0014-CCC',
    0x002e: 'ALL_FEAT-CCC',
    0x002f: 'ALL_REQ-CCC',
    0x0031: 'NOTIF-CCC',
}

ATT_OPS = {
    0x01: 'ERROR_RSP',
    0x02: 'MTU_REQ', 0x03: 'MTU_RSP',
    0x04: 'FIND_INFO_REQ', 0x05: 'FIND_INFO_RSP',
    0x08: 'READ_BY_TYPE_REQ', 0x09: 'READ_BY_TYPE_RSP',
    0x0a: 'READ_REQ', 0x0b: 'READ_RSP',
    0x0c: 'READ_BLOB_REQ', 0x0d: 'READ_BLOB_RSP',
    0x10: 'READ_BY_GRP_REQ', 0x11: 'READ_BY_GRP_RSP',
    0x12: 'WRITE_REQ', 0x13: 'WRITE_RSP',
    0x52: 'WRITE_CMD',
    0x1b: 'HANDLE_VALUE_NTF',
    0x1d: 'HANDLE_VALUE_IND', 0x1e: 'HANDLE_VALUE_CONF',
}

# Feature byte → name
FEAT = {
    0x09: 'CURRENT_TIME', 0x10: 'BLE_FEATURES', 0x11: 'BLE_SETTINGS',
    0x13: 'BASIC_SETTINGS', 0x1d: 'DST_WATCH', 0x1e: 'DST_SETTING',
    0x1f: 'WORLD_CITY', 0x20: 'VERSION_INFO', 0x22: 'APP_INFO',
    0x23: 'WATCH_NAME', 0x26: 'MODULE_ID', 0x28: 'WATCH_COND',
    0x3a: 'CONN_PARAM', 0x3b: 'ADVERT_PARAM', 0x3d: 'RECONNECT',
    0x43: 'TARGET_VALUES', 0x45: 'USER_PROFILE',
    0x47: 'SVC_DISC',
}

def xd(b, n=40):
    s = ' '.join(f'{x:02x}' for x in b[:n])
    return s + ('…' if len(b) > n else '')

def feat_name(b):
    return FEAT.get(b, f'0x{b:02x}')

def parse_acl(data, direction):
    if len(data) < 5:
        return
    total_len = struct.unpack('<H', data[3:5])[0]
    if len(data) < 5 + total_len:
        return
    l2 = data[5:]
    if len(l2) < 4:
        return
    l2_len = struct.unpack('<H', l2[0:2])[0]
    cid = struct.unpack('<H', l2[2:4])[0]
    if cid != 0x0004:   # only ATT
        return
    att = l2[4:]
    if not att:
        return
    op = att[0]

    dir_sym = '→W' if direction == 0 else '←W'

    if op == 0x12:  # WRITE_REQ
        if len(att) < 3:
            return
        h = struct.unpack('<H', att[1:3])[0]
        val = att[3:]
        hname = HANDLES.get(h, f'h{h:04x}')
        feat = feat_name(val[0]) if val else '?'
        print(f'  {dir_sym} WRITE_REQ  {hname:20s}  feat={feat:16s}  {xd(val)}')
    elif op == 0x52:  # WRITE_CMD
        if len(att) < 3:
            return
        h = struct.unpack('<H', att[1:3])[0]
        val = att[3:]
        hname = HANDLES.get(h, f'h{h:04x}')
        feat = feat_name(val[0]) if val else '?'
        print(f'  {dir_sym} WRITE_CMD  {hname:20s}  feat={feat:16s}  {xd(val)}')
    elif op == 0x1b:  # HANDLE_VALUE_NTF
        if len(att) < 3:
            return
        h = struct.unpack('<H', att[1:3])[0]
        val = att[3:]
        hname = HANDLES.get(h, f'h{h:04x}')
        feat = feat_name(val[0]) if val else '?'
        print(f'  {dir_sym} NOTIFY     {hname:20s}  feat={feat:16s}  {xd(val)}')
    elif op == 0x02:
        if len(att) >= 3:
            mtu = struct.unpack('<H', att[1:3])[0]
            print(f'  {dir_sym} MTU_REQ  mtu={mtu}')
    elif op == 0x03:
        if len(att) >= 3:
            mtu = struct.unpack('<H', att[1:3])[0]
            print(f'  {dir_sym} MTU_RSP  mtu={mtu}')


with open(LOG, 'rb') as f:
    hdr = f.read(16)
    assert hdr[:8] == b'btsnoop\x00', "Not a btsnoop file"
    version, datalink = struct.unpack('>II', hdr[8:16])
    print(f"BTSnoop version={version} datalink={datalink}")

    pkt_num = 0
    while True:
        rec_hdr = f.read(24)
        if len(rec_hdr) < 24:
            break
        orig_len, incl_len, flags, drops, ts = struct.unpack('>IIIIQ', rec_hdr)
        data = f.read(incl_len)
        direction = flags & 1   # 0=host→ctrl(→watch), 1=ctrl→host(←watch)
        pkt_type = data[0] if data else 0
        if pkt_type == 0x02:    # HCI ACL
            parse_acl(data, direction)
        pkt_num += 1
