#!/usr/bin/env python3
"""
Comprehensive analysis of all 5 btsnoop logs for Casio GBD-200 BLE probe.
Answers:
1. Does each log contain a `3d 01` notification on ALL_FEAT (h000e)?
2. What happens on h0011 (DATA_REQ_SP) and h0014 (CONVOY) after `3d 01`?
3. Complete sequence of WRITE ops on h0011 and h0014.
4. CCCD writes on h0012, h0015 after connection.
5. Any `39 00` / `39 02` / `39 03` traffic on h000e?

The handles below are the KNOWN handles used by the Python probe script.
We also auto-discover the actual handle numbers from the log.
"""
import struct, sys

LOGS_DIR = "/home/dakk/CasioGBD200BTLOG/dumps"

# Known handle IDs (from parse_init.py context)
# h000e = ALL_FEAT (0x000e), h0011 = DATA_REQ_SP (0x0011), h0014 = CONVOY (0x0014)
# h0012 = DATA_REQ_SP-CCC, h0015 = CONVOY-CCC
# BUT the parse_init.py uses 0x002d for ALL_FEAT, 0x0023 for DATA_REQ_SP, 0x0024 for CONVOY
# Let's check both handle spaces by scanning ALL handles

KNOWN_NAMES = {
    # From parse_init.py (one handle space)
    0x0023: 'DATA_REQ_SP(h0011)',
    0x0024: 'CONVOY(h0014)',
    0x002c: 'ALL_REQ',
    0x002d: 'ALL_FEAT',
    0x0025: 'h0011-CCC',
    0x0026: 'h0014-CCC',
    0x002e: 'ALL_FEAT-CCC',
    0x002f: 'ALL_REQ-CCC',
    0x0030: 'NOTIF',
    0x0031: 'NOTIF-CCC',
    # Raw handle space the user mentioned
    0x000e: 'ALL_FEAT(raw)',
    0x0011: 'DATA_REQ_SP(raw)',
    0x0012: 'DATA_REQ_SP-CCC(raw)',
    0x0014: 'CONVOY(raw)',
    0x0015: 'CONVOY-CCC(raw)',
}

ATT_OPS = {
    0x01: 'ERR_RSP',
    0x02: 'MTU_REQ', 0x03: 'MTU_RSP',
    0x04: 'FIND_INFO_REQ', 0x05: 'FIND_INFO_RSP',
    0x08: 'RBT_REQ', 0x09: 'RBT_RSP',
    0x0a: 'READ_REQ', 0x0b: 'READ_RSP',
    0x0c: 'READ_BLOB_REQ', 0x0d: 'READ_BLOB_RSP',
    0x10: 'RBG_REQ', 0x11: 'RBG_RSP',
    0x12: 'WRITE_REQ', 0x13: 'WRITE_RSP',
    0x52: 'WRITE_CMD',
    0x1b: 'NTF',
    0x1d: 'IND', 0x1e: 'IND_CONF',
}

def xd(b, n=48):
    s = ' '.join(f'{x:02x}' for x in b[:n])
    return s + ('...' if len(b) > n else '')

def parse_log(filename, log_num):
    """Parse a btsnoop log and extract all ATT events."""
    path = f"{LOGS_DIR}/{filename}"
    events = []  # list of (pkt_num, direction, op, handle, val_bytes)

    with open(path, 'rb') as f:
        hdr = f.read(16)
        if hdr[:8] != b'btsnoop\x00':
            print(f"  ERROR: Not a btsnoop file!")
            return events
        version, datalink = struct.unpack('>II', hdr[8:16])

        reassembly = {}
        pkt_num = 0

        while True:
            rec = f.read(24)
            if len(rec) < 24:
                break
            orig_len, incl_len, flags, drops, ts = struct.unpack('>IIIIQ', rec)
            data = f.read(incl_len)
            pkt_num += 1
            direction = flags & 1  # 0=host->ctrl(->watch), 1=ctrl->host(<-watch)

            if not data or data[0] != 0x02 or len(data) < 5:
                continue

            hw = struct.unpack('<H', data[1:3])[0]
            conn_h = hw & 0x0fff
            pb = (hw >> 12) & 0x03
            payload = data[5:]

            if pb in (0x00, 0x02):  # Start of L2CAP PDU
                if len(payload) < 4:
                    continue
                l2_len = struct.unpack('<H', payload[0:2])[0]
                cid = struct.unpack('<H', payload[2:4])[0]
                if cid != 0x0004:  # only ATT
                    continue
                att_data = payload[4:]
                if len(att_data) < l2_len:
                    # Need reassembly
                    reassembly[conn_h] = (bytearray(att_data), l2_len, pkt_num, direction)
                    continue
                att = bytes(att_data[:l2_len])
            elif pb == 0x01:  # Continuation
                if conn_h not in reassembly:
                    continue
                buf, expected, pkt_s, dir0 = reassembly[conn_h]
                buf.extend(payload)
                if len(buf) < expected:
                    reassembly[conn_h] = (buf, expected, pkt_s, dir0)
                    continue
                att = bytes(buf[:expected])
                direction = dir0
                pkt_num_use = pkt_s
                del reassembly[conn_h]
            else:
                continue

            if not att:
                continue
            op = att[0]

            if op in (0x02, 0x03):  # MTU
                mtu = struct.unpack('<H', att[1:3])[0] if len(att) >= 3 else 0
                events.append((pkt_num, direction, op, None, mtu.to_bytes(2, 'little')))
            elif op in (0x12, 0x52, 0x1b, 0x1d, 0x0a, 0x0b, 0x0c, 0x0d, 0x04, 0x05, 0x08, 0x09, 0x10, 0x11, 0x13, 0x1e, 0x01):
                if len(att) >= 3:
                    h = struct.unpack('<H', att[1:3])[0]
                    val = att[3:]
                    events.append((pkt_num, direction, op, h, val))
                elif op in (0x13, 0x1e):  # WRITE_RSP / IND_CONF (no handle)
                    events.append((pkt_num, direction, op, None, b''))

    return events, pkt_num

def analyze_log(log_num):
    filename = f"btsnoop_hci_{log_num}.log"
    print(f"\n{'='*70}")
    print(f"LOG {log_num}: {filename}")
    print(f"{'='*70}")

    result = parse_log(filename, log_num)
    if not isinstance(result, tuple):
        return
    events, total_pkts = result
    print(f"Total HCI packets: {total_pkts}")
    print(f"Total ATT events: {len(events)}")

    # --- Q5: Find all handles seen ---
    all_handles = set()
    for (pkt, dir, op, h, val) in events:
        if h is not None:
            all_handles.add(h)
    print(f"\nAll ATT handles seen: {sorted(f'h{h:04x}' for h in all_handles)}")

    # --- Q1: Find `3d 01` notification on ALL handles (look for 3d in value byte 0) ---
    # ALL_FEAT is h002d in parse_init.py BUT user says h000e — check both
    print(f"\n--- Q1: `3d 01` notifications (RECONNECT on ALL_FEAT) ---")
    feat_3d_events = []
    for (pkt, dir, op, h, val) in events:
        if op == 0x1b and val and val[0] == 0x3d:  # HANDLE_VALUE_NTF with feat=0x3d
            hname = KNOWN_NAMES.get(h, f'h{h:04x}')
            print(f"  [pkt {pkt}] ←W NTF h{h:04x}({hname}) val={xd(val)}")
            feat_3d_events.append((pkt, h, val))
    if not feat_3d_events:
        print("  NONE found")

    # --- Q5: Find `39 00` / `39 02` / `39 03` traffic ---
    print(f"\n--- Q5: `39 xx` traffic (TIME_REQ) on any handle ---")
    found_39 = False
    for (pkt, dir, op, h, val) in events:
        if val and val[0] == 0x39:
            hname = KNOWN_NAMES.get(h, f'h{h:04x}') if h is not None else '?'
            dir_s = '→W' if dir == 0 else '←W'
            print(f"  [pkt {pkt}] {dir_s} {ATT_OPS.get(op,'?')} h{h:04x}({hname}) val={xd(val)}")
            found_39 = True
    if not found_39:
        print("  NONE found")

    # --- Q3: Complete WRITE sequence on h0011/h0014 and h002d (ALL_FEAT handles) ---
    # First find which handles are the data/convoy handles
    # Look for 0x1c / 0x00 / 0x04 pattern (CONVOY handshake bytes)
    print(f"\n--- Q3/Q4: All WRITE ops and CCCDs (showing h002d, h002e, h002c, h002f, h0030, h0031, h0023, h0024, h0025, h0026 and any unknowns) ---")

    INTERESTING = {0x002d, 0x002e, 0x002c, 0x002f, 0x0030, 0x0031,
                   0x0023, 0x0024, 0x0025, 0x0026,
                   0x000e, 0x0011, 0x0012, 0x0014, 0x0015}

    # Also collect all write ops on ALL handles to find CONVOY pattern
    convoy_handles = set()
    for (pkt, dir, op, h, val) in events:
        if op in (0x12, 0x52) and val and val[0] in (0x1c, 0x00, 0x04):
            if h is not None:
                convoy_handles.add(h)

    data_req_handles = set()
    for (pkt, dir, op, h, val) in events:
        if op in (0x12, 0x52) and val and val[0] == 0x3d:
            if h is not None:
                data_req_handles.add(h)

    if convoy_handles:
        print(f"  Auto-detected CONVOY handles (0x1c/0x00/0x04 writes): {[f'h{h:04x}' for h in sorted(convoy_handles)]}")
    if data_req_handles:
        print(f"  Auto-detected handles with 3d writes: {[f'h{h:04x}' for h in sorted(data_req_handles)]}")

    SHOW_HANDLES = INTERESTING | convoy_handles | data_req_handles

    # Show all events on interesting handles
    for (pkt, dir, op, h, val) in events:
        if h is None:
            continue
        if h not in SHOW_HANDLES and h not in all_handles:
            continue
        # Show writes, CCCDs (2-byte write to CCC handle), and notifies
        hname = KNOWN_NAMES.get(h, f'h{h:04x}')
        dir_s = '→W' if dir == 0 else '←W'
        op_name = ATT_OPS.get(op, f'0x{op:02x}')

        # Filter: show writes, notifies, errors on interesting handles
        if op in (0x12, 0x52, 0x1b, 0x01, 0x13):
            if len(val) == 2 and op == 0x12:
                ccc = struct.unpack('<H', val)[0]
                print(f"  [pkt {pkt:5d}] {dir_s} {op_name:10s} h{h:04x}({hname:22s}) CCC={ccc:#06x}")
            else:
                print(f"  [pkt {pkt:5d}] {dir_s} {op_name:10s} h{h:04x}({hname:22s}) val={xd(val)}")

    # --- Q2: What happens AFTER 3d 01 on DATA_REQ_SP and CONVOY ---
    if feat_3d_events:
        first_3d_pkt = feat_3d_events[0][0]
        print(f"\n--- Q2: Events AFTER first `3d 01` at pkt {first_3d_pkt} on data/convoy handles ---")

        # Find the convoy handles
        # Look for handles that receive 0x1c writes
        convoy_h = sorted(convoy_handles) if convoy_handles else [0x0024, 0x0014]
        data_h_set = sorted(data_req_handles) if data_req_handles else [0x0023, 0x0011]

        print(f"  CONVOY handles: {[f'h{h:04x}' for h in convoy_h]}")
        print(f"  DATA_REQ handles: {[f'h{h:04x}' for h in data_h_set]}")

        after_events = [(pkt, dir, op, h, val) for (pkt, dir, op, h, val) in events if pkt > first_3d_pkt]

        # Find CONVOY handshake: 0x1c init, 0x00 ping, 0x04 cap
        convoy_seq = []
        for (pkt, dir, op, h, val) in after_events:
            if op in (0x12, 0x52, 0x1b) and val and val[0] in (0x1c, 0x00, 0x04):
                convoy_seq.append((pkt, dir, op, h, val))

        if convoy_seq:
            print(f"\n  CONVOY handshake sequence (0x1c/0x00/0x04 bytes) after pkt {first_3d_pkt}:")
            for (pkt, dir, op, h, val) in convoy_seq[:30]:
                hname = KNOWN_NAMES.get(h, f'h{h:04x}')
                dir_s = '→W' if dir == 0 else '←W'
                op_name = ATT_OPS.get(op, '?')
                print(f"    [pkt {pkt:5d}] {dir_s} {op_name:10s} h{h:04x}({hname}) val={xd(val)}")
        else:
            print(f"\n  No CONVOY handshake (0x1c/0x00/0x04) found after pkt {first_3d_pkt}")

        # Show ALL events on interesting handles after 3d
        relevant_after = [(pkt, dir, op, h, val) for (pkt, dir, op, h, val) in after_events
                          if h in (SHOW_HANDLES | set(convoy_h) | set(data_h_set))]
        if relevant_after:
            print(f"\n  All events on data/convoy/CCCD handles after pkt {first_3d_pkt} (first 50):")
            for (pkt, dir, op, h, val) in relevant_after[:50]:
                hname = KNOWN_NAMES.get(h, f'h{h:04x}')
                dir_s = '→W' if dir == 0 else '←W'
                op_name = ATT_OPS.get(op, f'0x{op:02x}')
                if len(val) == 2 and op == 0x12:
                    ccc = struct.unpack('<H', val)[0]
                    print(f"    [pkt {pkt:5d}] {dir_s} {op_name:10s} h{h:04x}({hname:22s}) CCC={ccc:#06x}")
                else:
                    print(f"    [pkt {pkt:5d}] {dir_s} {op_name:10s} h{h:04x}({hname:22s}) val={xd(val)}")

def main():
    for i in range(1, 6):
        analyze_log(i)
    print(f"\n{'='*70}")
    print("DONE")

if __name__ == '__main__':
    main()
