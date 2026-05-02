#!/usr/bin/env python3
"""Full ATT dump — finds all unique handles used, then shows all GATT exchanges."""
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "btsnoop_hci_5.log"
START = int(sys.argv[2]) if len(sys.argv) > 2 else 0
COUNT = int(sys.argv[3]) if len(sys.argv) > 3 else 99999

ATT_OPS = {
    0x01: 'ERR_RSP', 0x02: 'MTU_REQ', 0x03: 'MTU_RSP',
    0x04: 'FIND_INFO_REQ', 0x05: 'FIND_INFO_RSP',
    0x06: 'FIND_BY_TYPE_REQ', 0x07: 'FIND_BY_TYPE_RSP',
    0x08: 'READ_BY_TYPE_REQ', 0x09: 'READ_BY_TYPE_RSP',
    0x0a: 'READ_REQ', 0x0b: 'READ_RSP',
    0x10: 'READ_BY_GRP_REQ', 0x11: 'READ_BY_GRP_RSP',
    0x12: 'WRITE_REQ', 0x13: 'WRITE_RSP',
    0x52: 'WRITE_CMD',
    0x1b: 'NTF', 0x1d: 'IND', 0x1e: 'IND_CNF',
}

# Known Casio feature IDs
FEAT = {
    0x09: 'TIME', 0x10: 'BLE_FEAT', 0x11: 'BLE_SET',
    0x13: 'BASIC', 0x1d: 'DST_WATCH', 0x1e: 'DST_SET',
    0x1f: 'WORLD_CITY', 0x20: 'VER_INFO', 0x22: 'APP_INFO',
    0x23: 'WATCH_NAME', 0x26: 'MODULE_ID', 0x28: 'WATCH_COND',
    0x3a: 'CONN_PARAM', 0x3b: 'ADV_PARAM', 0x3d: 'RECONNECT',
    0x43: 'TARGET_VAL', 0x45: 'USER_PROF',
    0x47: 'SVC_DISC',
}

def xd(b, n=48):
    s = ' '.join(f'{x:02x}' for x in b[:n])
    return s + ('...' if len(b) > n else '')

def feat_tag(val):
    if not val:
        return ''
    f = val[0]
    name = FEAT.get(f, '')
    return f'[feat=0x{f:02x}{("="+name) if name else ""}]'

def parse_pkt(data, direction, pkt_num):
    if not data or data[0] != 0x02:
        return
    if len(data) < 9:
        return
    l2 = data[5:]
    if len(l2) < 4:
        return
    cid = struct.unpack('<H', l2[2:4])[0]
    if cid != 0x0004:
        return
    att = l2[4:]
    if not att:
        return
    op = att[0]
    op_name = ATT_OPS.get(op, f'op=0x{op:02x}')
    dir_s = '→W' if direction == 0 else '←W'

    if op in (0x12, 0x52):  # WRITE_REQ / WRITE_CMD
        if len(att) < 3:
            return
        h = struct.unpack('<H', att[1:3])[0]
        val = att[3:]
        tag = feat_tag(val)
        print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} h{h:04x}  {tag:30s}  {xd(val)}')
    elif op == 0x1b:  # NTF
        if len(att) < 3:
            return
        h = struct.unpack('<H', att[1:3])[0]
        val = att[3:]
        tag = feat_tag(val)
        print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} h{h:04x}  {tag:30s}  {xd(val)}')
    elif op in (0x02, 0x03):  # MTU
        mtu = struct.unpack('<H', att[1:3])[0] if len(att) >= 3 else 0
        print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} mtu={mtu}')
    elif op == 0x08:  # READ_BY_TYPE_REQ
        if len(att) >= 5:
            s = struct.unpack('<H', att[1:3])[0]
            e = struct.unpack('<H', att[3:5])[0]
            uuid = xd(att[5:], 16)
            print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} range=0x{s:04x}-0x{e:04x} uuid={uuid}')
    elif op == 0x09:  # READ_BY_TYPE_RSP
        print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} {xd(att[1:], 48)}')
    elif op == 0x10:  # READ_BY_GRP_REQ
        if len(att) >= 5:
            s = struct.unpack('<H', att[1:3])[0]
            e = struct.unpack('<H', att[3:5])[0]
            print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} range=0x{s:04x}-0x{e:04x}')
    elif op == 0x11:  # READ_BY_GRP_RSP
        print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} {xd(att[1:], 48)}')
    elif op == 0x01:  # ERROR_RSP
        if len(att) >= 5:
            req = att[1]; h = struct.unpack('<H', att[2:4])[0]; code = att[4]
            print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} req=0x{req:02x} h{h:04x} code=0x{code:02x}')
    elif op == 0x13:  # WRITE_RSP
        pass
    else:
        print(f'[{pkt_num:5d}] {dir_s} {op_name:12s} {xd(att, 32)}')


with open(LOG, 'rb') as f:
    f.read(16)  # header
    pkt_num = 0
    shown = 0
    while shown < COUNT:
        rec_hdr = f.read(24)
        if len(rec_hdr) < 24:
            break
        orig_len, incl_len, flags, drops, ts = struct.unpack('>IIIIQ', rec_hdr)
        data = f.read(incl_len)
        direction = flags & 1
        if pkt_num >= START:
            parse_pkt(data, direction, pkt_num)
            shown += 1
        pkt_num += 1
