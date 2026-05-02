#!/usr/bin/env python3
"""
Casio GBD-200 BLE Protocol Audit Script
Targeted at btsnoop_hci_3.log

Questions answered:
  1. Init request 0x1c bytes & Java correctness
  2. Init response 0x06 bytes & surrounding traffic
  3. Missing writes between 0x1c and 0x1d
  4. Session list 0x1d request bytes & offset
  5. Session list 0x05 response XOR-decoded bytes, popcount, session count
  6. Notification enablement (write-descriptor) before first 0x1c
  7. ACK format (0x04) bytes
  8. Handle traffic directions

Handle legend:
  0x0011 = CASIO_DATA_REQUEST_SP  (phone -> watch writes)
  0x0014 = CASIO_CONVOY           (watch -> phone notifications)
"""

import subprocess
import sys

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

SEP = "=" * 72

def run_tshark(*extra_fields, display_filter=None, custom_filter=None):
    args = ['tshark', '-r', LOG, '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', 'btatt.handle',
            '-e', 'btatt.value',
            '-e', 'bthci_acl.src.bd_addr',
            '-e', 'bthci_acl.dst.bd_addr',
            ]
    for f in extra_fields:
        args += ['-e', f]
    if display_filter:
        args += ['-Y', display_filter]
    if custom_filter:
        args += ['-Y', custom_filter]
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout.strip()

def parse_frames(raw_output):
    frames = []
    for line in raw_output.split('\n'):
        if not line.strip():
            continue
        parts = line.strip().split('\t')
        # parts: frame_no, time_rel, handle, value, src, dst [, extra...]
        try:
            fno = int(parts[0])
            time_rel = float(parts[1]) if parts[1] else 0.0
            handle = int(parts[2], 16) if parts[2] else 0
            value_hex = parts[3].replace(':', '') if len(parts) > 3 else ''
            value = bytes.fromhex(value_hex) if value_hex else b''
            src = parts[4] if len(parts) > 4 else ''
            dst = parts[5] if len(parts) > 5 else ''
            frames.append({
                'fno': fno, 'time': time_rel, 'handle': handle,
                'value': value, 'src': src, 'dst': dst
            })
        except Exception:
            pass
    return frames

def xor_decode(data):
    """XOR decode type-0x05 CONVOY: byte[0] unchanged, bytes[1:] XOR 0xFF"""
    if len(data) == 0:
        return data
    return bytes([data[0]] + [b ^ 0xFF for b in data[1:]])

def hexfmt(data, max_bytes=None):
    if max_bytes:
        data = data[:max_bytes]
    return ' '.join(f'{b:02x}' for b in data)

def popcount(n):
    return bin(n).count('1')

def bcd(b):
    return ((b >> 4) & 0xF) * 10 + (b & 0xF)

# ─── Load all ATT traffic ────────────────────────────────────────────────────
print(SEP)
print("Loading all ATT frames from btsnoop_hci_3.log ...")
print(SEP)

# Get all btatt frames
raw = run_tshark(display_filter='btatt.handle')
all_att = parse_frames(raw)
print(f"Total ATT frames: {len(all_att)}")

# Separate by handle
h0011 = [f for f in all_att if f['handle'] == 0x0011]
h0014 = [f for f in all_att if f['handle'] == 0x0014]
other_att = [f for f in all_att if f['handle'] not in (0x0011, 0x0014)]

print(f"  handle 0x0011 (DATA_REQUEST_SP): {len(h0011)} frames")
print(f"  handle 0x0014 (CONVOY):          {len(h0014)} frames")
print(f"  other ATT handles:               {len(other_att)} frames")

# Combined sorted timeline
timeline = [(f['fno'], '0011', f) for f in h0011] + \
           [(f['fno'], '0014', f) for f in h0014]
timeline.sort(key=lambda x: x[0])

# ─── QUESTION 8: Handle traffic directions ──────────────────────────────────
print()
print(SEP)
print("Q8: HANDLE TRAFFIC DIRECTIONS")
print(SEP)

# Identify BD_ADDR of the device (watch) and phone
# Phone typically initiates writes; watch sends notifications
src_addresses_0011 = set()
src_addresses_0014 = set()
for f in h0011:
    src_addresses_0011.add((f['src'], f['dst']))
for f in h0014:
    src_addresses_0014.add((f['src'], f['dst']))

print(f"  h0011 src->dst pairs: {src_addresses_0011}")
print(f"  h0014 src->dst pairs: {src_addresses_0014}")

# Count writes vs notifications by checking ATT opcode
# Use tshark with btatt.opcode field
raw_op = subprocess.run(
    ['tshark', '-r', LOG, '-Y', 'btatt.handle == 0x0011 || btatt.handle == 0x0014',
     '-T', 'fields', '-e', 'frame.number', '-e', 'btatt.handle',
     '-e', 'btatt.opcode', '-e', 'btatt.value'],
    capture_output=True, text=True
).stdout.strip()

opcode_0011 = {}
opcode_0014 = {}
for line in raw_op.split('\n'):
    parts = line.strip().split('\t')
    if len(parts) < 3: continue
    try:
        fno = int(parts[0])
        handle = int(parts[1], 16)
        opcode = parts[2]
        val = parts[3].replace(':', '') if len(parts) > 3 else ''
        if handle == 0x0011:
            opcode_0011[fno] = opcode
        elif handle == 0x0014:
            opcode_0014[fno] = opcode
    except:
        pass

op_0011_counts = {}
op_0014_counts = {}
for op in opcode_0011.values():
    op_0011_counts[op] = op_0011_counts.get(op, 0) + 1
for op in opcode_0014.values():
    op_0014_counts[op] = op_0014_counts.get(op, 0) + 1

print(f"\n  h0011 opcode counts: {op_0011_counts}")
print(f"  h0014 opcode counts: {op_0014_counts}")
print()
print("  BTT opcode meanings:")
print("    0x12 = Write Request (phone -> watch, expects response)")
print("    0x52 = Write Without Response (phone -> watch)")
print("    0x1b = Handle Value Notification (watch -> phone)")
print("    0x1d = Handle Value Indication (watch -> phone, expects confirm)")
print()
# Check for reverse traffic (watch writes on 0x0011, or phone notifies 0x0014)
raw_dir = subprocess.run(
    ['tshark', '-r', LOG, '-Y', 'btatt.handle == 0x0011 || btatt.handle == 0x0014',
     '-T', 'fields', '-e', 'frame.number', '-e', 'btatt.handle',
     '-e', 'btatt.opcode', '-e', 'bthci_acl.src.bd_addr'],
    capture_output=True, text=True
).stdout.strip()

print("  First 20 frames with source addresses:")
count = 0
for line in raw_dir.split('\n'):
    parts = line.strip().split('\t')
    if len(parts) >= 4 and parts[3]:
        print(f"    frame {parts[0]:>5}  h={parts[1]}  op={parts[2]}  src={parts[3]}")
        count += 1
        if count >= 20:
            break

# ─── QUESTION 6: Notification enablement before first 0x1c ──────────────────
print()
print(SEP)
print("Q6: GATT WRITE-DESCRIPTOR / ENABLE-NOTIFICATION BEFORE FIRST 0x1c")
print(SEP)

# Find the frame number of the first 0x1c request
first_1c_frame = None
for f in h0011:
    if len(f['value']) >= 2 and f['value'][0] == 0x00 and f['value'][1] == 0x1c:
        first_1c_frame = f['fno']
        break

print(f"  First 0x1c request at frame: {first_1c_frame}")

if first_1c_frame:
    # Get ALL ATT traffic before the first 0x1c
    raw_before = subprocess.run(
        ['tshark', '-r', LOG,
         '-Y', f'btatt && frame.number < {first_1c_frame}',
         '-T', 'fields',
         '-e', 'frame.number',
         '-e', 'btatt.handle',
         '-e', 'btatt.opcode',
         '-e', 'btatt.value',
         '-e', 'btgatt.uuid16',
         '-e', 'btatt.uuid16'],
        capture_output=True, text=True
    ).stdout.strip()

    print(f"\n  ALL ATT frames before first 0x1c (frame {first_1c_frame}):")
    write_desc_handles = []
    for line in raw_before.split('\n'):
        if not line.strip():
            continue
        parts = line.strip().split('\t')
        try:
            fno = int(parts[0])
            handle = int(parts[1], 16) if parts[1] else 0
            opcode = parts[2] if len(parts) > 2 else ''
            val = parts[3].replace(':', '') if len(parts) > 3 else ''
            # 0x52 = write without response, 0x12 = write, 0x02 = read
            op_names = {
                '0x02': 'ReadReq', '0x03': 'ReadResp',
                '0x12': 'WriteReq', '0x13': 'WriteResp',
                '0x52': 'WriteNoResp',
                '0x16': 'WriteReq(desc)',
                '0x04': 'FindInfo', '0x05': 'FindInfoResp',
                '0x08': 'ReadByTypeReq', '0x09': 'ReadByTypeResp',
                '0x10': 'ReadByGroupReq', '0x11': 'ReadByGroupResp',
                '0x1b': 'Notification',
            }
            op_str = op_names.get(opcode, opcode)
            val_str = val[:40] + ('...' if len(val) > 40 else '')
            print(f"    frame {fno:>5}  h=0x{handle:04x}  op={op_str}({opcode})  val={val_str}")
            # CCCD handle writes (value 0x0100 = enable notify, 0x0200 = enable indicate)
            if opcode in ('0x12', '0x52') and val in ('0100', '0200', '0300', '0000'):
                write_desc_handles.append((fno, handle, val))
        except Exception:
            pass

    if write_desc_handles:
        print(f"\n  CCCD writes (notification enable) found:")
        for fno, handle, val in write_desc_handles:
            status = 'ENABLE NOTIFY' if val == '0100' else 'ENABLE INDICATE' if val == '0200' else 'DISABLE' if val == '0000' else val
            print(f"    frame {fno}: handle 0x{handle:04x}  value={val} ({status})")
    else:
        print(f"\n  No CCCD writes found before first 0x1c.")

# ─── QUESTION 1: Init request (0x1c) exact bytes ────────────────────────────
print()
print(SEP)
print("Q1: INIT REQUEST (0x1c) — EXACT BYTES")
print(SEP)

init_requests = []
for f in h0011:
    if len(f['value']) >= 2 and f['value'][0] == 0x00 and f['value'][1] == 0x1c:
        init_requests.append(f)

print(f"  Found {len(init_requests)} init request(s):")
for f in init_requests:
    print(f"    frame {f['fno']:>5}  @{f['time']:.3f}s")
    print(f"      RAW bytes ({len(f['value'])}): {hexfmt(f['value'])}")
    print()

# Java sendFeatureRequest(FEATURE_INIT=0x1c, offset=0, param=0) produces:
# { 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
java_init = bytes([0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
print(f"  Java sendFeatureRequest(0x1c, 0, 0) would send:")
print(f"    {hexfmt(java_init)}")
print()
for f in init_requests:
    match = f['value'] == java_init
    print(f"    frame {f['fno']}: {'MATCH' if match else 'MISMATCH'}")
    if not match and len(f['value']) >= len(java_init):
        for i, (a, b) in enumerate(zip(f['value'], java_init)):
            if a != b:
                print(f"      byte[{i}]: capture=0x{a:02x}, java=0x{b:02x}")

# ─── QUESTION 2: Init response (0x06) exact bytes ───────────────────────────
print()
print(SEP)
print("Q2: INIT RESPONSE (0x06) — ALL CONVOY RESPONSES AROUND INIT")
print(SEP)

if init_requests:
    first_init_frame = init_requests[0]['fno']
    last_init_frame = init_requests[-1]['fno']

    # Find all CONVOY frames within ±100 frames of the first init
    print(f"  CONVOY frames (h0014) around first init request (frame {first_init_frame}):")
    window_start = first_init_frame - 5
    window_end   = first_init_frame + 150

    for fno, hh, f in timeline:
        if hh == '0014' and window_start <= fno <= window_end:
            ctype = f['value'][0] if f['value'] else 0
            type_str = '0x06 (INIT_RESP)' if ctype == 0x06 else f'0x{ctype:02x} (DATA)' if ctype == 0x05 else f'0x{ctype:02x}'
            print(f"    frame {fno:>5}  @{f['time']:.3f}s  type={type_str}  len={len(f['value'])}  hex={hexfmt(f['value'])[:60]}")

    # Show all 0x06 responses in the entire capture
    print(f"\n  ALL 0x06 CONVOY frames in entire capture:")
    for f in h0014:
        if f['value'] and f['value'][0] == 0x06:
            print(f"    frame {f['fno']:>5}  @{f['time']:.3f}s  {hexfmt(f['value'])}")

    # Show 0x05 responses immediately before the first 0x06
    print(f"\n  Any 0x05 CONVOY frames before first 0x1c or between 0x1c and first 0x06:")
    first_06_frame = None
    for f in h0014:
        if f['value'] and f['value'][0] == 0x06:
            first_06_frame = f['fno']
            break
    if first_06_frame:
        for f in h0014:
            if f['value'] and f['value'][0] == 0x05 and f['fno'] < first_06_frame + 5:
                dec = xor_decode(f['value'])
                print(f"    frame {f['fno']:>5}  @{f['time']:.3f}s  RAW={hexfmt(f['value'])[:40]}  XOR={hexfmt(dec)[:40]}")

# ─── QUESTION 3: Missing writes between 0x1c and 0x1d ───────────────────────
print()
print(SEP)
print("Q3: ALL WRITES ON h0011 BETWEEN 0x1c AND 0x1d REQUEST")
print(SEP)

if init_requests:
    first_init_frame = init_requests[0]['fno']

    # Find first 0x1d request
    first_1d_frame = None
    for f in h0011:
        if len(f['value']) >= 2 and f['value'][0] == 0x00 and f['value'][1] == 0x1d:
            first_1d_frame = f['fno']
            break

    print(f"  Init (0x1c) at frame: {first_init_frame}")
    print(f"  Session list (0x1d) at frame: {first_1d_frame}")

    if first_1d_frame:
        print(f"\n  ALL h0011 writes between frames {first_init_frame} and {first_1d_frame}:")
        for f in h0011:
            if first_init_frame <= f['fno'] <= first_1d_frame:
                val = f['value']
                cmd_type = val[0] if val else 0xff
                fid = val[1] if len(val) > 1 else 0xff
                type_names = {0x00: 'REQUEST', 0x04: 'ACK', 0x01: 'UNK_01', 0x02: 'UNK_02', 0x03: 'UNK_03'}
                cmd_str = type_names.get(cmd_type, f'0x{cmd_type:02x}')
                print(f"    frame {f['fno']:>5}  @{f['time']:.3f}s  cmd={cmd_str}  feat=0x{fid:02x}  {hexfmt(val)}")

        # Check Java code: after 0x06 response, Java immediately sends 0x1d
        print(f"\n  Java code path after 0x06:")
        print(f"    onCharacteristicChanged -> if(convoyType==0x06) && state==INIT:")
        print(f"      state = WAITING_FOR_LIST")
        print(f"      sendFeatureRequest(FEATURE_LIST, SESSION_LIST_BASE, 0x01)")
        print(f"    i.e. Java sends 0x1d directly after 0x06 with NO intermediate writes")

        # Count writes between init and first 0x1d
        intermediate = [f for f in h0011 if first_init_frame < f['fno'] < first_1d_frame]
        print(f"\n  Intermediate h0011 writes (exclusive): {len(intermediate)}")
        for f in intermediate:
            print(f"    frame {f['fno']:>5}  {hexfmt(f['value'])}")

# ─── QUESTION 4: Session list (0x1d) request bytes ──────────────────────────
print()
print(SEP)
print("Q4: SESSION LIST REQUEST (0x1d) — EXACT BYTES")
print(SEP)

list_requests = []
for f in h0011:
    if len(f['value']) >= 2 and f['value'][0] == 0x00 and f['value'][1] == 0x1d:
        list_requests.append(f)

print(f"  Found {len(list_requests)} session list request(s):")
SESSION_LIST_BASE = 0x46a0
for f in list_requests:
    val = f['value']
    offset = (val[3] | (val[4] << 8)) if len(val) >= 5 else 0
    param = val[7] if len(val) >= 8 else 0
    print(f"    frame {f['fno']:>5}  @{f['time']:.3f}s")
    print(f"      bytes: {hexfmt(val)}")
    print(f"      offset field (bytes[3:5] LE): 0x{offset:04x} = {offset}")
    print(f"      param (byte[7]): 0x{param:02x}")
    print(f"      SESSION_LIST_BASE = 0x{SESSION_LIST_BASE:04x} = {SESSION_LIST_BASE}")
    match_base = (offset == SESSION_LIST_BASE)
    print(f"      offset matches SESSION_LIST_BASE: {match_base}")
    print()

# Java: sendFeatureRequest(FEATURE_LIST, SESSION_LIST_BASE, 0x01)
java_list = bytes([0x00, 0x1d, 0x00,
                   SESSION_LIST_BASE & 0xff,
                   (SESSION_LIST_BASE >> 8) & 0xff,
                   0x00, 0x00, 0x01, 0x00, 0x00])
print(f"  Java sendFeatureRequest(0x1d, 0x46a0, 0x01) would send:")
print(f"    {hexfmt(java_list)}")
if list_requests:
    cap = list_requests[0]['value']
    match = (cap == java_list)
    print(f"    Capture match: {match}")
    if not match:
        print(f"    Capture bytes: {hexfmt(cap)}")
        for i in range(max(len(cap), len(java_list))):
            a = cap[i] if i < len(cap) else -1
            b = java_list[i] if i < len(java_list) else -1
            if a != b:
                print(f"      byte[{i}]: capture=0x{a:02x}, java=0x{b:02x}")

# ─── QUESTION 5: Session list response XOR-decoded bytes ────────────────────
print()
print(SEP)
print("Q5: SESSION LIST RESPONSE — XOR-DECODED CONVOY 0x05 PACKETS")
print(SEP)

if list_requests:
    first_1d = list_requests[0]['fno']
    # Find first ACK on h0011 (type 0x04) or next request after the 0x1d
    next_h0011_after_1d = None
    for f in h0011:
        if f['fno'] > first_1d:
            next_h0011_after_1d = f['fno']
            break

    print(f"  Collecting 0x05 CONVOY frames after frame {first_1d}:")
    response_packets = []
    for f in h0014:
        if f['fno'] > first_1d:
            if next_h0011_after_1d and f['fno'] > next_h0011_after_1d:
                break
            if f['value'] and f['value'][0] == 0x05:
                response_packets.append(f)

    # Actually, session list response may be only one packet
    # Show all 0x05 frames in the window
    print(f"  CONVOY 0x05 frames for 0x1d response:")
    combined_payload = bytearray()
    for f in response_packets:
        dec = xor_decode(f['value'])
        # XOR-decoded format: [0]=0x05, [1:3]=LE16 payload length, [3:]=payload
        pkt_type = dec[0]
        pkt_len = (dec[1] | (dec[2] << 8)) if len(dec) >= 3 else 0
        payload = dec[3:] if len(dec) > 3 else b''
        combined_payload.extend(payload)
        print(f"    frame {f['fno']:>5}  RAW: {hexfmt(f['value'])}")
        print(f"             DEC: {hexfmt(dec)}")
        print(f"             type=0x{pkt_type:02x} pkt_len={pkt_len} payload_len={len(payload)}")
        if payload:
            print(f"             payload: {hexfmt(payload)}")
        print()

    # Show all the combined payload
    if combined_payload:
        print(f"  Combined payload ({len(combined_payload)} bytes): {hexfmt(bytes(combined_payload))}")
        print()

        # Analyze byte [9] (data[9] in Java = combined_payload[9-3] = combined_payload[6]?)
        # Wait: The Java data[] array IS the raw GATT value (before our xor_decode).
        # In onCharacteristicChanged, 'data' = f['value'] as bytes.
        # The code XOR-decodes in place: for i in range(1, len(data)): data[i] = ~data[i]
        # So data[0] = raw[0] = 0x05 (unchanged)
        #    data[1] = ~raw[1]
        #    data[9] = ~raw[9]
        # Then parseSessionList(data) checks data.length > 9 and reads data[9]
        # "data[9] is XOR-decoded; raw byte = ~data[9]"

        # So in our response_packets:
        #   raw[9] = f['value'][9]
        #   decoded_data[9] = xor_decode(f['value'])[9] = ~raw[9]
        # And: rawSessionByte = (~decoded_data[9]) & 0xff = raw[9]

        if response_packets:
            first_resp = response_packets[0]
            raw_value = first_resp['value']
            dec_value = xor_decode(raw_value)

            print(f"  Session byte analysis (first CONVOY 0x05 packet, frame {first_resp['fno']}):")
            print(f"    raw[9]  = 0x{raw_value[9]:02x} = {raw_value[9]}")
            print(f"    dec[9]  = 0x{dec_value[9]:02x} = {dec_value[9]}")
            raw9 = raw_value[9]  # = ~dec[9] & 0xff
            dec9 = dec_value[9]  # = ~raw9 & 0xff
            print(f"    Java: rawSessionByte = (~data[9]) & 0xff = (~dec[9]) & 0xff = raw[9] = 0x{raw9:02x}")
            total_sessions = popcount(raw9)
            print(f"    popcount(0x{raw9:02x}) = popcount({bin(raw9)}) = {total_sessions}")
            newest_offset = SESSION_LIST_BASE + 0x40 + total_sessions
            print(f"    newestOffset = 0x{SESSION_LIST_BASE:04x} + 0x40 + {total_sessions} = 0x{newest_offset:04x}")
            print(f"    Expected: 4 sessions in this capture? -> raw9=0x0f, popcount=4, offset=0x{SESSION_LIST_BASE+0x44:04x}")

            # Also show bytes around index 9 in context
            print(f"\n  Context around byte[9] (raw bytes 5-15 of first packet):")
            for i in range(5, min(16, len(raw_value))):
                print(f"    raw[{i}] = 0x{raw_value[i]:02x}  dec[{i}] = 0x{dec_value[i]:02x}")

# ─── QUESTION 7: ACK format ─────────────────────────────────────────────────
print()
print(SEP)
print("Q7: ACK (type 0x04) EXACT BYTES")
print(SEP)

ack_frames = []
for f in h0011:
    if f['value'] and f['value'][0] == 0x04:
        ack_frames.append(f)

print(f"  Found {len(ack_frames)} ACK frames on h0011:")
for f in ack_frames:
    val = f['value']
    feat = val[1] if len(val) > 1 else 0xff
    print(f"    frame {f['fno']:>5}  @{f['time']:.3f}s  feat=0x{feat:02x}  bytes: {hexfmt(val)}")

# Java sendAck(featureId):
# { 0x04, featureId, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
print()
for feat_id in [0x1c, 0x1d, 0x1e, 0x1f, 0x20]:
    java_ack = bytes([0x04, feat_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    print(f"  Java sendAck(0x{feat_id:02x}): {hexfmt(java_ack)}")

print()
# Compare captures to Java format
print("  Comparison with capture:")
for f in ack_frames:
    val = f['value']
    feat = val[1] if len(val) > 1 else 0
    java_ack = bytes([0x04, feat, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    match = (val == java_ack)
    print(f"    frame {f['fno']}  feat=0x{feat:02x}: {'MATCH' if match else 'MISMATCH'}")
    if not match:
        print(f"      cap:  {hexfmt(val)}")
        print(f"      java: {hexfmt(java_ack)}")
        for i in range(max(len(val), len(java_ack))):
            a = val[i] if i < len(val) else -1
            b = java_ack[i] if i < len(java_ack) else -1
            if a != b:
                print(f"      byte[{i}]: cap=0x{a:02x}, java=0x{b:02x}")

# ─── Full timeline (first ~60 relevant frames) ─────────────────────────────
print()
print(SEP)
print("FULL PROTOCOL TIMELINE (init → session list, first 80 relevant frames)")
print(SEP)

feat_names = {0x1c: 'INIT', 0x1d: 'LIST', 0x1e: 'SUMMARY', 0x1f: 'TRACK', 0x20: 'TRACK2'}
cmd_names = {0x00: 'REQ', 0x04: 'ACK', 0x01: 'CMD1', 0x02: 'CMD2', 0x03: 'CMD3'}

count = 0
for fno, hh, f in timeline:
    val = f['value']
    if not val:
        continue

    if hh == '0011':
        cmd = val[0]
        feat = val[1] if len(val) > 1 else 0
        cmd_str = cmd_names.get(cmd, f'0x{cmd:02x}')
        feat_str = feat_names.get(feat, f'0x{feat:02x}')
        extra = ''
        if cmd == 0x00:
            offset = (val[3] | (val[4] << 8)) if len(val) >= 5 else 0
            param  = val[7] if len(val) >= 8 else 0
            extra = f' offset=0x{offset:04x} param=0x{param:02x}'
        print(f"  [{fno:5d}] PHONE→WATCH  h0011  {cmd_str} {feat_str}{extra}")
        print(f"           {hexfmt(val)}")
    else:
        ctype = val[0]
        if ctype == 0x06:
            print(f"  [{fno:5d}] WATCH→PHONE  h0014  type=0x06 (INIT_OK)")
            print(f"           {hexfmt(val)}")
        elif ctype == 0x05:
            dec = xor_decode(val)
            pkt_len = (dec[1] | (dec[2] << 8)) if len(dec) >= 3 else 0
            print(f"  [{fno:5d}] WATCH→PHONE  h0014  type=0x05 (DATA) len={pkt_len}")
            print(f"           RAW: {hexfmt(val[:20])}{'...' if len(val)>20 else ''}")
            print(f"           DEC: {hexfmt(dec[:20])}{'...' if len(dec)>20 else ''}")
        else:
            print(f"  [{fno:5d}] WATCH→PHONE  h0014  type=0x{ctype:02x}")
            print(f"           {hexfmt(val[:20])}")

    count += 1
    if count >= 80:
        print("  ... (truncated at 80 frames) ...")
        break

# ─── Summary: Discrepancies with Java code ──────────────────────────────────
print()
print(SEP)
print("DISCREPANCY ANALYSIS vs Java FetchSportActivityOperation.java")
print(SEP)

# Check the ACK timing - in Java, ACK is sent AFTER parseSessionList()
# which is called from onCharacteristicChanged when state==WAITING_FOR_LIST
# Let's verify sequence: 0x1d REQ -> 0x05 RESP -> 0x04 ACK(0x1d)

if list_requests:
    print("\n  Expected sequence from Java:")
    print("    1. PHONE sends 0x1d REQ (WAITING_FOR_LIST)")
    print("    2. WATCH sends 0x05 CONVOY (session list data)")
    print("    3. Java calls parseSessionList() -> sendAck(FEATURE_LIST)")
    print("    4. Java calls sendFeatureRequest(FEATURE_SUMMARY, ...)")
    print()

    first_1d_frame = list_requests[0]['fno']
    print(f"  Actual sequence after 0x1d request (frame {first_1d_frame}):")
    next_frames = [(fno, hh, f) for fno, hh, f in timeline if fno >= first_1d_frame]
    for fno, hh, f in next_frames[:20]:
        val = f['value']
        if hh == '0011':
            cmd = val[0]
            feat = val[1] if len(val) > 1 else 0
            cmd_str = cmd_names.get(cmd, f'0x{cmd:02x}')
            feat_str = feat_names.get(feat, f'0x{feat:02x}')
            print(f"    [{fno:5d}] PHONE  {cmd_str} feat={feat_str}  {hexfmt(val)}")
        else:
            ctype = val[0]
            if ctype == 0x05:
                dec = xor_decode(val)
                print(f"    [{fno:5d}] WATCH  0x05 DATA  DEC: {hexfmt(dec[:16])}...")
            else:
                print(f"    [{fno:5d}] WATCH  0x{ctype:02x}  {hexfmt(val[:16])}")

# ─── Check doPerform() ordering ─────────────────────────────────────────────
print()
print(SEP)
print("Q6 DETAIL: Does Java doPerform() send notifications before 0x1c?")
print(SEP)
print("  Java doPerform():")
print("    enableNotifications(true)  <- GATT write-descriptor for h0011+h0014")
print("    sendFeatureRequest(0x1c, 0, 0)  <- immediate write on h0011")
print()
print("  In AbstractBTLEOperation, enableNotifications() and sendFeatureRequest()")
print("  both call builder.queue() separately.")
print("  TransactionBuilder queues ops as a transaction; they are sequenced.")
print("  So notification enables SHOULD happen before the 0x1c write.")
print()
print("  Capture verification:")
if first_1c_frame:
    # Check if write-descriptor frames appear before the first 0x1c
    # We already checked this in Q6 above.
    print(f"    First 0x1c at frame {first_1c_frame}")
    print("    See Q6 output above for descriptor writes before this frame.")

# ─── Look for CCCD handles specifically ─────────────────────────────────────
print()
print(SEP)
print("CCCD WRITE-DESCRIPTOR DETAILS (all frames)")
print(SEP)

# CCCD writes are typically on handle = characteristic_handle + 1
# DATA_REQUEST_SP = 0x0011, so CCCD might be 0x0012
# CONVOY = 0x0014, so CCCD might be 0x0015
raw_desc = subprocess.run(
    ['tshark', '-r', LOG,
     '-Y', 'btatt.opcode == 0x52 || btatt.opcode == 0x12',
     '-T', 'fields',
     '-e', 'frame.number',
     '-e', 'frame.time_relative',
     '-e', 'btatt.handle',
     '-e', 'btatt.opcode',
     '-e', 'btatt.value'],
    capture_output=True, text=True
).stdout.strip()

print("  All Write Request / Write Without Response frames:")
for line in raw_desc.split('\n'):
    if not line.strip():
        continue
    parts = line.strip().split('\t')
    try:
        fno = int(parts[0])
        t = float(parts[1])
        handle = int(parts[2], 16) if parts[2] else 0
        opcode = parts[3]
        val = parts[4].replace(':', '') if len(parts) > 4 else ''
        op_name = 'WriteReq' if opcode == '0x12' else 'WriteNoResp'
        notify_flag = ''
        if val == '0100':
            notify_flag = ' [ENABLE NOTIFY]'
        elif val == '0000':
            notify_flag = ' [DISABLE NOTIFY]'
        elif val == '0200':
            notify_flag = ' [ENABLE INDICATE]'
        print(f"    [{fno:5d}] @{t:.3f}s  h=0x{handle:04x}  {op_name}  val={val}{notify_flag}")
    except:
        pass

print()
print(SEP)
print("DONE")
print(SEP)
