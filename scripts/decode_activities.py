#!/usr/bin/env python3
"""
Decode Casio GBD-200 sport activities from a BLE HCI snoop log.

Implements exactly the same parsing rules as FetchSportActivityOperation.java:
  - CONVOY 0x05 XOR decode (bytes[1:] ^ 0xff)
  - Session list bitmask → session count
  - 0x1e summary field offsets (BCD timestamps, IEEE 754 distance, etc.)
  - 0x1f track block assembly + 7-byte record parsing for max pace
"""
import subprocess, os, struct, json, argparse

LOG = os.path.join(os.path.dirname(__file__), 'btsnoop_hci_3.log')

SESSION_LIST_BASE    = 0x46a0
TRACK_BLOCK_HEADER   = 15
TRACK_RECORD_STRIDE  = 7
TRACK_BLOCK_ADDR_LAST = 0xffff

# data[]-relative offsets (data[0]=0x05 type, data[1:3]=LE16 len, data[3:]=payload)
OFFSET_RECORD_COUNT_LO = 137
OFFSET_RECORD_COUNT_HI = 138
OFFSET_SEGMENT_COUNT   = 145
OFFSET_START_YEAR_LO   = 150  # 7-byte BCD: [year_lo, year_hi, month, day, hour, min, sec]
OFFSET_END_YEAR_LO     = 157
OFFSET_TRACK_ADDR_LO   = 165
OFFSET_TRACK_ADDR_HI   = 166
OFFSET_DISTANCE_FLOAT  = 172  # LE32 IEEE 754, km
OFFSET_DURATION_MIN    = 177
OFFSET_DURATION_SEC    = 178
OFFSET_AVG_PACE_MIN    = 179
OFFSET_AVG_PACE_SEC    = 180
OFFSET_CALORIES        = 181
OFFSET_CADENCE         = 185
MIN_DATA_LENGTH        = OFFSET_CADENCE + 1

# ── BLE capture helpers ───────────────────────────────────────────────────────

def tshark_frames(log, handle):
    out = subprocess.run(
        ['tshark', '-r', log, '-Y', f'btatt.handle == {handle}',
         '-T', 'fields', '-e', 'frame.number', '-e', 'btatt.value'],
        capture_output=True, text=True).stdout.strip()
    res = []
    for line in out.split('\n'):
        p = line.strip().split('\t')
        try:
            res.append((int(p[0]), bytes.fromhex(p[1].replace(':', ''))))
        except Exception:
            pass
    return res

def xor_decode(d):
    b = bytearray(d)
    for i in range(1, len(b)):
        b[i] ^= 0xff
    return bytes(b)

# ── Response assembler ────────────────────────────────────────────────────────

def collect_responses(log):
    """
    Walk all BLE frames in chronological order and group watch→phone CONVOY
    0x05 payloads by the (feature_id, offset) of the phone command that triggered them.

    Returns dict: (feature_id, offset) → bytes
      where bytes is laid out as data[] in Java:
        data[0]    = 0x05  (synthetic, matches Java convention)
        data[1:3]  = LE16 total payload length
        data[3:]   = assembled XOR-decoded payload
    """
    f11 = tshark_frames(log, '0x0011')  # phone → watch (feature requests, ACKs)
    f14 = tshark_frames(log, '0x0014')  # watch → phone (CONVOY responses)
    all_frames = sorted(
        [(n, '11', d) for n, d in f11] + [(n, '14', d) for n, d in f14]
    )

    responses    = {}
    cur_feature  = None
    cur_offset   = None
    cur_buf      = bytearray()

    def flush():
        if cur_feature is not None and cur_buf:
            key = (cur_feature, cur_offset)
            if key not in responses:   # keep first occurrence (duplicates discarded)
                total = len(cur_buf)
                responses[key] = bytes([0x05, total & 0xff, (total >> 8) & 0xff]) + bytes(cur_buf)

    for _n, h, d in all_frames:
        if h == '11' and len(d) >= 2 and d[0] == 0x00:
            # Phone feature request: [0x00, feature, 0x00, offset_lo, offset_hi, ...]
            feature = d[1]
            offset  = (d[3] | (d[4] << 8)) if len(d) >= 5 else 0
            if feature != cur_feature or offset != cur_offset:
                flush()
                cur_buf     = bytearray()
                cur_feature = feature
                cur_offset  = offset
        elif h == '14' and cur_feature is not None and len(d) >= 1 and d[0] == 0x05:
            dec = xor_decode(d)
            cur_buf.extend(dec[3:])

    flush()
    return responses

# ── Parsing helpers ───────────────────────────────────────────────────────────

def bcd_dec(b):
    return ((b >> 4) & 0xf) * 10 + (b & 0xf)

def bcd_timestamp(data, offset):
    year  = bcd_dec(data[offset + 1]) * 100 + bcd_dec(data[offset])
    month = bcd_dec(data[offset + 2])
    day   = bcd_dec(data[offset + 3])
    hour  = bcd_dec(data[offset + 4])
    minute = bcd_dec(data[offset + 5])
    sec   = bcd_dec(data[offset + 6])
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"

def fmt_pace(seconds_per_km):
    if not seconds_per_km:
        return "---"
    return f"{seconds_per_km // 60}'{seconds_per_km % 60:02d}''/km"

def fmt_duration(total_seconds):
    m, s = divmod(total_seconds, 60)
    return f"{m}m{s:02d}s"

# ── Track block parser ────────────────────────────────────────────────────────

def parse_track_blocks(responses, first_block_addr):
    """
    Follow the linked list of 0x1f track blocks starting at first_block_addr.
    Returns (max_pace_seconds, total_records, block_info_list).
    max_pace_seconds is the minimum s/km seen across all clean records, or 0.
    """
    min_pace = None
    total_records = 0
    block_info = []
    block_addr = first_block_addr

    while True:
        key = (0x1f, block_addr)
        if key not in responses:
            block_info.append({'addr': block_addr, 'error': 'not found in capture'})
            break

        # Strip the 3-byte synthetic CONVOY header ([0x05][len_lo][len_hi]) added by
        # collect_responses so indices match the Java processCompletedTrackBlock() directly.
        block = responses[key][3:]

        if len(block) < TRACK_BLOCK_HEADER:
            block_info.append({'addr': block_addr, 'error': f'too short ({len(block)} bytes)'})
            break

        next_addr = block[5] | (block[6] << 8)
        rec_count = 0

        for off in range(TRACK_BLOCK_HEADER, len(block) - TRACK_RECORD_STRIDE + 1, TRACK_RECORD_STRIDE):
            if block[off] == 0xff:
                break
            rec_count += 1
            # Clean records: bytes[5:6] == 0
            if block[off + 5] == 0 and block[off + 6] == 0:
                pace_min = block[off + 2]
                pace_sec = block[off + 3]
                if pace_min > 0:
                    pace_s = pace_min * 60 + pace_sec
                    if min_pace is None or pace_s < min_pace:
                        min_pace = pace_s

        block_info.append({
            'addr':      block_addr,
            'bytes':     len(block),
            'records':   rec_count,
            'next_addr': next_addr,
        })
        total_records += rec_count

        if next_addr == TRACK_BLOCK_ADDR_LAST:
            break
        block_addr = next_addr

    return (min_pace or 0), total_records, block_info

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Decode GBD-200 sport activities from HCI snoop log')
    parser.add_argument('log', nargs='?', default=LOG, help='path to btsnoop HCI log')
    parser.add_argument('--json', action='store_true', help='output JSON instead of text')
    args = parser.parse_args()

    responses = collect_responses(args.log)

    # ── Session list ──────────────────────────────────────────────────────────
    list_key = (0x1d, SESSION_LIST_BASE)
    if list_key not in responses:
        print('ERROR: no 0x1d session list response found in capture')
        return

    list_data = responses[list_key]
    if len(list_data) <= 9:
        print('ERROR: session list response too short')
        return

    raw_session_byte = (~list_data[9]) & 0xff
    total_sessions   = bin(raw_session_byte).count('1')
    newest_offset    = SESSION_LIST_BASE + 0x40 + total_sessions

    activities = []

    for i in range(1, total_sessions + 1):
        summary_offset = SESSION_LIST_BASE + 0x40 + i
        key = (0x1e, summary_offset)

        if key not in responses:
            activities.append({'offset': f'0x{summary_offset:04x}', 'error': 'summary not found in capture'})
            continue

        data = responses[key]
        if len(data) < MIN_DATA_LENGTH:
            activities.append({'offset': f'0x{summary_offset:04x}', 'error': f'summary too short ({len(data)} bytes)'})
            continue

        record_count  = data[OFFSET_RECORD_COUNT_LO] | (data[OFFSET_RECORD_COUNT_HI] << 8)
        segment_count = data[OFFSET_SEGMENT_COUNT]
        start_time    = bcd_timestamp(data, OFFSET_START_YEAR_LO)
        end_time      = bcd_timestamp(data, OFFSET_END_YEAR_LO)
        track_addr    = data[OFFSET_TRACK_ADDR_LO] | (data[OFFSET_TRACK_ADDR_HI] << 8)
        distance_km   = struct.unpack_from('<f', data, OFFSET_DISTANCE_FLOAT)[0]
        distance_m    = round(distance_km * 1000)
        duration_s    = data[OFFSET_DURATION_MIN] * 60 + data[OFFSET_DURATION_SEC]
        avg_pace_s    = data[OFFSET_AVG_PACE_MIN] * 60 + data[OFFSET_AVG_PACE_SEC]
        calories      = data[OFFSET_CALORIES]
        cadence       = data[OFFSET_CADENCE]

        # Track blocks
        max_pace_s, track_records, block_info = (0, 0, [])
        if track_addr not in (0, TRACK_BLOCK_ADDR_LAST):
            max_pace_s, track_records, block_info = parse_track_blocks(responses, track_addr)

        activities.append({
            'offset':         f'0x{summary_offset:04x}',
            'start_time':     start_time,
            'end_time':       end_time,
            'duration_s':     duration_s,
            'distance_m':     distance_m,
            'distance_km':    round(distance_km, 3),
            'avg_pace_s_km':  avg_pace_s,
            'max_pace_s_km':  max_pace_s,
            'calories_kcal':  calories,
            'cadence_spm':    cadence,
            'segments':       segment_count,
            'record_count':   record_count,
            'track_addr':     f'0x{track_addr:04x}',
            'track_records':  track_records,
            'track_blocks':   block_info,
        })

    if args.json:
        print(json.dumps({
            'session_list': {
                'raw_byte':       f'0x{raw_session_byte:02x}',
                'total_sessions': total_sessions,
                'newest_offset':  f'0x{newest_offset:04x}',
            },
            'activities': activities,
        }, indent=2))
        return

    # ── Text output ───────────────────────────────────────────────────────────
    print(f"Session list: raw=0x{raw_session_byte:02x}  {total_sessions} activity(ies)  newest=0x{newest_offset:04x}")
    print()

    for act in activities:
        print('=' * 60)
        if 'error' in act:
            print(f"Activity @ {act['offset']}: {act['error']}")
            continue

        print(f"Activity @ {act['offset']}")
        print(f"  Start:     {act['start_time']}")
        print(f"  End:       {act['end_time']}")
        print(f"  Duration:  {fmt_duration(act['duration_s'])}  ({act['duration_s']}s)")
        print(f"  Distance:  {act['distance_m']} m  ({act['distance_km']:.3f} km)")
        print(f"  Avg pace:  {fmt_pace(act['avg_pace_s_km'])}")
        print(f"  Max pace:  {fmt_pace(act['max_pace_s_km']) if act['max_pace_s_km'] else '---'}")
        print(f"  Calories:  {act['calories_kcal']} kcal")
        print(f"  Cadence:   {act['cadence_spm']} spm")
        print(f"  Segments:  {act['segments']}")
        print(f"  Records:   {act['record_count']} (summary)  /  {act['track_records']} (from track)")
        print(f"  TrackAddr: {act['track_addr']}")
        for b in act['track_blocks']:
            if 'error' in b:
                print(f"    block 0x{b['addr']:04x}: {b['error']}")
            else:
                print(f"    block 0x{b['addr']:04x}: {b['bytes']} bytes  {b['records']} records  next=0x{b['next_addr']:04x}")

if __name__ == '__main__':
    main()
