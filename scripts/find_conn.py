#!/usr/bin/env python3
"""Dump HCI connection events and LE meta events to find the Casio watch connection."""
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "btsnoop_hci_5.log"

def mac(b):
    return ':'.join(f'{x:02x}' for x in reversed(b))

def xd(b, n=32):
    return ' '.join(f'{x:02x}' for x in b[:n]) + ('...' if len(b) > n else '')

with open(LOG, 'rb') as f:
    hdr = f.read(16)
    pkt_num = 0
    while True:
        rec_hdr = f.read(24)
        if len(rec_hdr) < 24:
            break
        orig_len, incl_len, flags, drops, ts = struct.unpack('>IIIIQ', rec_hdr)
        data = f.read(incl_len)
        direction = flags & 1
        pkt_num += 1

        if not data:
            continue

        pkt_type = data[0]

        # HCI Event (0x04)
        if pkt_type == 0x04 and len(data) >= 3:
            evt_code = data[1]
            param_len = data[2]
            params = data[3:]

            # LE Meta Event (0x3e)
            if evt_code == 0x3e and len(params) >= 1:
                sub = params[0]
                if sub == 0x01:  # LE Connection Complete
                    if len(params) >= 19:
                        status = params[1]
                        conn_h = struct.unpack('<H', params[2:4])[0]
                        role = params[4]
                        addr_type = params[5]
                        addr = mac(params[6:12])
                        interval = struct.unpack('<H', params[12:14])[0]
                        latency = struct.unpack('<H', params[14:16])[0]
                        timeout = struct.unpack('<H', params[16:18])[0]
                        print(f"[{pkt_num:5d}] LE_CONN_COMPLETE  status={status} handle=0x{conn_h:04x} addr={addr} role={'master' if role==0 else 'slave'} interval={interval} latency={latency} timeout={timeout}")
                elif sub == 0x02:  # LE Advertising Report
                    pass  # skip
                elif sub == 0x03:  # LE Connection Update Complete
                    if len(params) >= 9:
                        status = params[1]
                        conn_h = struct.unpack('<H', params[2:4])[0]
                        interval = struct.unpack('<H', params[4:6])[0]
                        latency = struct.unpack('<H', params[6:8])[0]
                        timeout = struct.unpack('<H', params[8:10])[0] if len(params) >= 10 else 0
                        print(f"[{pkt_num:5d}] LE_CONN_UPDATE     handle=0x{conn_h:04x} interval={interval} latency={latency} timeout={timeout}")

            # Connection Complete (0x03)
            elif evt_code == 0x03 and len(params) >= 11:
                status = params[0]
                conn_h = struct.unpack('<H', params[1:3])[0]
                addr = mac(params[3:9])
                print(f"[{pkt_num:5d}] CONN_COMPLETE  status={status} handle=0x{conn_h:04x} addr={addr}")

            # Disconnection Complete (0x05)
            elif evt_code == 0x05 and len(params) >= 4:
                status = params[0]
                conn_h = struct.unpack('<H', params[1:3])[0]
                reason = params[3]
                print(f"[{pkt_num:5d}] DISCONN_COMPLETE  handle=0x{conn_h:04x} reason=0x{reason:02x}")

        # HCI ACL: dump MTU exchange to spot connection start
        elif pkt_type == 0x02 and len(data) >= 9:
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
            if op in (0x02, 0x03):  # MTU REQ/RSP
                mtu = struct.unpack('<H', att[1:3])[0] if len(att) >= 3 else 0
                dir_s = '→W' if direction == 0 else '←W'
                conn_h = struct.unpack('<H', data[1:3])[0] & 0x0fff
                op_name = 'MTU_REQ' if op == 0x02 else 'MTU_RSP'
                print(f"[{pkt_num:5d}] {dir_s} {op_name}  conn=0x{conn_h:04x} mtu={mtu}")
