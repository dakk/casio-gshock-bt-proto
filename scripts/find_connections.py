#!/usr/bin/env python3
"""Find all BLE connections in the btsnoop log by parsing HCI events."""
import struct, sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "btsnoop_hci_5.log"
TARGET_MAC = sys.argv[2].upper() if len(sys.argv) > 2 else "F1:3C:89:52:D6:34"

def mac_bytes_to_str(b):
    return ':'.join(f'{x:02x}' for x in reversed(b)).upper()

def xd(b, n=32):
    return ' '.join(f'{x:02x}' for x in b[:n]) + ('...' if len(b) > n else '')

# Track all connection handles seen in ACL data
acl_handles = {}
conn_events = {}
all_evt_codes = {}

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

        if not data:
            continue

        pkt_type = data[0]

        # HCI Events
        if pkt_type == 0x04 and len(data) >= 3:
            evt_code = data[1]
            params = data[3:]
            all_evt_codes[evt_code] = all_evt_codes.get(evt_code, 0) + 1

            # LE Meta Event
            if evt_code == 0x3e and len(params) >= 1:
                sub = params[0]
                if sub == 0x01 and len(params) >= 19:  # LE Connection Complete
                    status = params[1]
                    conn_h = struct.unpack('<H', params[2:4])[0]
                    role = 'central' if params[4] == 0 else 'peripheral'
                    addr_type = params[5]
                    addr = mac_bytes_to_str(params[6:12])
                    interval = struct.unpack('<H', params[12:14])[0]
                    is_target = '  *** CASIO ***' if addr == TARGET_MAC else ''
                    print(f"[{pkt_num:5d}] LE_CONN  status={status} h=0x{conn_h:04x} {role} addr={addr}{is_target}")
                    conn_events[conn_h] = {'addr': addr, 'pkt': pkt_num}
                elif sub == 0x0a and len(params) >= 9:  # LE Enhanced Connection Complete
                    status = params[1]
                    conn_h = struct.unpack('<H', params[2:4])[0]
                    role = 'central' if params[4] == 0 else 'peripheral'
                    addr_type = params[5]
                    addr = mac_bytes_to_str(params[6:12])
                    is_target = '  *** CASIO ***' if addr == TARGET_MAC else ''
                    print(f"[{pkt_num:5d}] LE_ENH_CONN  status={params[1]} h=0x{conn_h:04x} {role} addr={addr}{is_target}")
                    conn_events[conn_h] = {'addr': addr, 'pkt': pkt_num}

            # Disconnection Complete
            elif evt_code == 0x05 and len(params) >= 4:
                conn_h = struct.unpack('<H', params[1:3])[0]
                reason = params[3]
                addr = conn_events.get(conn_h, {}).get('addr', '??:??:??:??:??:??')
                print(f"[{pkt_num:5d}] DISCONN  h=0x{conn_h:04x} addr={addr} reason=0x{reason:02x}")

        # ACL: track connection handles
        elif pkt_type == 0x02 and len(data) >= 5:
            handle_word = struct.unpack('<H', data[1:3])[0]
            conn_h = handle_word & 0x0fff
            acl_handles[conn_h] = acl_handles.get(conn_h, 0) + 1

print("\n--- ACL connection handles seen ---")
for h, cnt in sorted(acl_handles.items()):
    addr = conn_events.get(h, {}).get('addr', 'unknown')
    print(f"  h=0x{h:04x}  pkts={cnt:5d}  addr={addr}")

print("\n--- HCI event codes seen ---")
for code, cnt in sorted(all_evt_codes.items()):
    print(f"  evt=0x{code:02x}  count={cnt}")
