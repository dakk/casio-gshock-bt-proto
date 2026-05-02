#!/usr/bin/env python3
"""Dump raw LE Meta events and classic BT events to understand connection structure."""
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "btsnoop_hci_5.log"

def mac(b):
    return ':'.join(f'{x:02x}' for x in reversed(b)).upper()

def xd(b, n=32):
    return ' '.join(f'{x:02x}' for x in b[:n]) + ('...' if len(b) > n else '')

CONN_EVT = {
    0x03: 'CONN_COMPLETE',
    0x05: 'DISCONN_COMPLETE',
    0x06: 'AUTH_COMPLETE',
    0x07: 'REMOTE_NAME_REQ_COMPLETE',
    0x08: 'ENCRYPT_CHANGE',
    0x0b: 'REMOTE_FEAT_COMPLETE',
    0x0c: 'REMOTE_VER_COMPLETE',
    0x0d: 'COMMAND_STATUS',
}

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

        if not data or data[0] != 0x04:
            continue

        evt_code = data[1]
        params = data[3:]

        if evt_code == 0x3e:  # LE Meta
            sub = params[0] if params else 0xff
            print(f"[{pkt_num:5d}] LE_META sub=0x{sub:02x}  {xd(params)}")

        elif evt_code == 0x03:  # Connection Complete (Classic)
            if len(params) >= 11:
                status = params[0]
                conn_h = struct.unpack('<H', params[1:3])[0]
                addr = mac(params[3:9])
                link_type = params[9]
                print(f"[{pkt_num:5d}] CLASSIC_CONN status={status} h=0x{conn_h:04x} addr={addr} link_type={link_type}")

        elif evt_code == 0x05:  # Disconnection Complete
            if len(params) >= 4:
                status = params[0]
                conn_h = struct.unpack('<H', params[1:3])[0]
                reason = params[3]
                print(f"[{pkt_num:5d}] DISCONN  status={status} h=0x{conn_h:04x} reason=0x{reason:02x}")

        elif evt_code in CONN_EVT:
            print(f"[{pkt_num:5d}] {CONN_EVT[evt_code]}  {xd(params)}")
