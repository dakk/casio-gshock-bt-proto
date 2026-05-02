#!/usr/bin/env python3
"""Full decoder for Casio GBD-200 sport activity BLE packets"""

# Ground truth for the 2026-04-29 15:23 local (13:23 UTC) session:
# Distance: 60 meters
# Duration: 78 seconds
# Avg pace: 1140 s/km (19'00'')
# Max pace: 654 s/km (10'54'')
# Calories: 3 kcal
# Cadence: 106 fpm
# Records: 39

def xor_all(data):
    return bytes(b ^ 0xff for b in data)

# Feature 0x1e (session summary) - frame 5483
# Strip last 2 bytes CRC: eb27 -> actual data ends before that
f1e_hex = "0500ffff0100000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f8ffecffeefeffffd8ffffffecfffffffefffffff7d9dffbd6ecdcb8d9dffbd6ecdafaff5fb8ffff3fb4ffb3ea73c2fffeedecfffcffffff95ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb27"
f1e_raw = bytes.fromhex(f1e_hex)
f1e_dec = xor_all(f1e_raw[:-2])  # strip CRC
print(f"Feature 0x1e decoded ({len(f1e_dec)} bytes):")
pl = f1e_dec[0] | (f1e_dec[1] << 8)
print(f"  payload_len = {pl}")
print("  Non-zero, non-ff bytes:")
for i, b in enumerate(f1e_dec):
    if b != 0 and b != 0xff:
        print(f"    [{i:3d}] = 0x{b:02x} = {b}")

print()
print("Feature 0x1e: searching for known values:")
for i in range(len(f1e_dec)-3):
    v8 = f1e_dec[i]
    v16le = f1e_dec[i] | (f1e_dec[i+1] << 8)
    v16be = (f1e_dec[i] << 8) | f1e_dec[i+1]
    if v8 == 60: print(f"  dist8  [{i}]={v8}")
    if v16le == 60: print(f"  dist16le [{i}]={v16le}")
    if v16le == 654: print(f"  maxpace16le [{i}]={v16le}")
    if v16be == 654: print(f"  maxpace16be [{i}]={v16be}")
    if v8 == 0x0a and f1e_dec[i+1] == 0x36: print(f"  maxpace_bcd 10:54 [{i}]")
    if v16le == 6: print(f"  val6_16le [{i}]={v16le}")

print()

# Feature 0x1f (previous session track) - frames 5511-5663
# We need to figure out if these have the format:
# [type=0x05][XOR'd data...]
# and how to reassemble the stream

f1f_frames = {
    5511: "0500eefebdfeff00000000000000000000fffffdfffffffffffffbfffffffffffff9fffffffffffff7fffffffffffff5ffff9ffffffff3ffff9ffffffff1ffffabffffffefffffabffffffedffffb7ffffffebffffb1ffffffe9ffffa5ffffffe7ffff93ffffffe5ffff8dffffffe3ffff7bffffffe1ffff7bffffffdfffff87ffffffddffff8dffffffdbffff8dffffffd9ffff93ffffffd7ffff93ffffffd5ffff87ffffffd3ffff87ffffffd1ffff87ffffffcfffff81ffffffcdffff87ffffffcbf5c993ffffffc9f5c999ffffffc7f5c999ffffffc5f5c99ffffffefff5c999fffffefdf5c999fffffefbf5c993fffffef9f5c993fffffef7f5c993fffffef5f5c999fffffef3f3f193fffffef1f3f193fffffeeff3f193fffffeedf3f193ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    5515: "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001288",
    5533: "05000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    5537: "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    5554: "0500000000000000fffbcbf9e763fffffbc9f9ee5dfffffbc7f9ee63fffffbc5f9ee5dfffffafff9ee5dfffffafdf9ee5dfffffafbf9ee63fffffaf9f9e75dfffffaf7f9e763fffffaf5f9e763fffffaf3f9e75dfffffaf1f9e75dfffffaeff9e763fffffaedf9ee5dfffffaebf9ee5dfffffae9f9f563fffffae7f9f563fffffae5f9fc5dfffffae3f9fc63fffffae1f9fc5dfffffadff9fc5dfffffaddf9f55dfffffadbf9f563fffffad9f9ee5dfffffad7f9ee63fffffad5f9e763fffffad3f9e75dfffffad1f9df5dfffffacff9df63fffffacdf9df5dfffffacbf9df5dfffffac9f9e75dfffffac7f9e75dfffffac5f9ee5dfffff9fff9ee5dfffff9fdf9ee5dfffff9fbf9ee63fffff9f9f9f55dfffff9f7f9f55dfffff9f5f9ee63fffff9f3f9ee5dfffff9f1f9e75dfffff9eff9e75dfffff9edf9df5dfffff9ebf9df5dfffff9e9f9df5dfffff9e7f9df5dfffff9e5f9d75dfffff9e3f9d75dfffff9e1f9d75dfffff9dff9d75dfffff9ddf9df5dfffff9dbf9df5dfffff9d9f9ee5dfffff9d7f9ee5dfffff9d5f9fc63fffff9d3f9fc5dfffff9d1f9fc63fffff9cff9fc63fffff9cdfacd5dfffff9cbfacd5dfffff9c9fa",
    5558: "05d35dfffff9c7fad35dfffff9c5facd5dfffff8fffacd63fffff8fdf9fc5dfffff8fbf9fc63fffff8f9fac65dfffff8f7fac65dfffff8f5f9fc5dfffff8f3f9fc5dfffff8f1f9ee5dffff1d39",
    5575: "05f8eff9ee63fffff8edf9e75dfffff8ebf9e75dfffff8e9f9f563fffff8e7f9f55dfffff8e5f9f55dfffff8e3f9f563fffff8e1f9f55dfffff8dff9f55dfffff8ddf9f55dfffff8dbf9f55dfffff8d9f9f557fffff8d7f9f55dfffff8d5f9e75dfffff8d3f9e75dfffff8d1f7f85dfffff8cff9ee63fffff8cdf8c75dfffff8cbf9ee5dfffff8c9f8d25dfffff8c7f9ee5dfffff8c5f8d25dfffff7fff9f55dfffff7fdf8dd5dfffff7fbf9fc5dfffff7f9f9fc5dfffff7f7f9fc5dfffff7f5f9fc5dfffff7f3fac65dfffff7f1fac663fffff7effacd5dfffff7edfacd5dfffff7ebfac663fffff7e9fac65dfffff7e7f9fc5dfffff7e5f9fc63fffff7e3f9f55dfffff7e1f9f55dfffff7dff9e75dfffff7ddf9e75dfffff7dbf9df57fffff7d9f9df5dfffff7d7f9df5dfffff7d5f9df5dfffff7d3f9df5dfffff7d1f9df63fffff7cff9d75dfffff7cdf9d75dfffff7cbf9e763fffff7c9f9e75dfffff7c7f9ee5dfffff7c5f9ee5dfffff6fff9ee5dfffff6fdf9ee5dfffff6fbf9f55dfffff6f9f9f55dfffff6f7f9f563fffff6f5f9f55dfffff6f3f9e75dfffff6f1f9e75dfffff6eff9df5dfffff6edf9df57fffff6ebf9e7",
    5579: "055dfffff6e9f9e75dfffff6e7f9df5dfffff6e5f9df5dfffff6e3f9df5dfffff6e1f9df5dfffff6dff9df5dfffff6ddf9df5dfffff6dbf9df5dfffff6d9f9df5dfffff6d7f9d75dfffff68ca8",
    5596: "05d5f9d75dfffff6d3f9df5dfffff6d1f9df5dfffff6cff9e763fffff6cdf9e75dfffff6cbf9e75dfffff6c9f9e763fffff6c7f9e75dfffff6c5f9e75dfffff5fff9e763fffff5fdf9e75dfffff5fbf9e75dfffff5f9f9e75dfffff5f7f9ee5dfffff5f5f9ee5dfffff5f3f9ee5dfffff5f1f9ee5dfffff5eff9ee5dfffff5edf9ee5dfffff5ebf9ee57fffff5e9f9ee5dfffff5e7f9ee57fffff5e5f9ee5dfffff5e3f9df57fffff5e1f9df5dfffff5dff9df57fffff5ddf9df5dfffff5dbf9e75dfffff5d9f9e75dfffff5d7f9ee5dfffff5d5f9ee5dfffff5d3f9e75dfffff5d1f9e75dfffff5cff9e75dfffff5cdf9e75dfffff5cbf9ee5dfffff5c9f9ee5dfffff5c7f9ee57fffff5c5f9ee5dfffff4fff9ee57fffff4fdf9ee5dfffff4fbf9ee5dfffff4f9f9ee5dfffff4f7f9f55dfffff4f5f9f55dfffff4f3f9f55dfffff4f1f9f557fffff4eff9ee5dfffff4edf9ee57fffff4ebf9f55dfffff4e9f9f55dfffff4e7f9fc5dfffff4e5f9fc5dfffff4e3f9f55dfffff4e1f9f55dfffff4dff9ee5dfffff4ddf9ee5dfffff4dbf9f55dfffff4d9f9f55dfffff4d7f9ee5dfffff4d5f9ee57fffff4d3f9ee5dfffff4d1f9ee5d",
    5600: "05fffff4cff9ee5dfffff4cdf9ee5dfffff4cbf8d263fffff4c9f9ee63fffff4c7f8c75dfffff4c5f9ee63fffff3fff8c75dfffff3fdf9ee5dfffff3fbf8c757fffff3f9f9e75dfffff3f7c257",
    5617: "05f8c757fffff3f5f9e75dfffff3f3f9e757fffff3f1f9e75dfffff3eff9e757fffff3edf9e75dfffff3ebf9e75dfffff3e9f9df5dfffff3e7f9df5dfffff3e5f9e75dfffff3e3f9e75dfffff3e1f9ee57fffff3dff9ee5dfffff3ddf8d257fffff3dbf9fc5dfffff3d9f8dd5dfffff3d7f9f55dfffff3d5f8dd5dfffff3d3f9fc63fffff3d1f8dd5dfffff3cff9fc5dfffff3cdf8dd63fffff3cbf8dd5dfffff3c9f9fc5dfffff3c7f8d263fffff3c5f9ee5dfffff2fff9ee5dfffff2fdf9ee5dfffff2fbf9fc5dfffff2f9faf85dfffff2f7f9f55dfffff2f5fafc5dfffff2f3fafc63fffff2f1f9fc5dfffff2effbc55dfffff2edfacd5dfffff2ebfade5dfffff2e9fade57fffff2e7fad95dfffff2e5f9cf57fffff2e3fade5dfffff2e1f9c757fffff2dffade5dfffff2ddfade57fffff2dbfad95dfffff2d9fad95dfffff2d7fac65dfffff2d5fac65dfffff2d3fac65dfffff2d1fac65dfffff2cffac65dfffff2cdfafc5dfffff2cbf9f55dfffff2c9fafc5dfffff2c7f9fc5dfffff2c5faf85dfffff1fff9fc5dfffff1fdfafc5dfffff1fbf9f563fffff1f9fafc5dfffff1f7f9fc5dfffff1f5fad363fffff1f3fad363ff",
    5621: "05fff1f1fad35dfffff1effad363fffff1edf9c763fffff1ebfad95dfffff1e9f9c75dfffff1e7fad363fffff1e5f8f15dfffff1e3fac65dfffff1e1f8d263fffff1dff9fc63fffff1ddf8e3ce",
    5638: "05d25dfffff1dbf9ee63fffff1d9f9ee5dfffff1d7f9e75dfffff1d5f9e75dfffff1d3f9e763fffff1d1f9e75dfffff1cff9e763fffff1cdf9e763fffff1cbf9d75dfffff1c9f9d75dfffff1c7f9d763fffff1c5f9d75dfffff0fff9d75dfffff0fdf9d763fffff0fbf9e75dfffff0f9f9e75dfffff0f7f9e763fffff0f5f9e75dfffff0f3f9e75dfffff0f1f9e763fffff0eff9ee5dfffff0edf9ee5dfffff0ebf9fc5dfffff0e9f9fc5dfffff0e7f9ee5dfffff0e5f9ee5dfffff0e3f9fc5dfffff0e1f9fc63fffff0dff9fc5dfffff0ddf9fc5dfffff0dbf9fc63fffff0d9f9fc5dfffff0d7f9fc5dfffff0d5f9fc63fffff0d3f9fc5dfffff0d1f9fc5dfffff0cff9f55dfffff0cdf9f55dfffff0cbf9f55dfffff0c9f9f55dfffff0c7f8d25dfffff0c5f9fc5dffffeffff8d25dffffeffdf9f55dffffeffbf8dd5dffffeff9f9fc5dffffeff7f8dd63ffffeff5f9f55dffffeff3f8dd5dffffeff1f9f563ffffefeff9f55dffffefedf9e75dffffefebf9e763ffffefe9f9df5dffffefe7f9df5dffffefe5f9d763ffffefe3f9d763ffffefe1f9df5dffffefdff9df63ffffefddf9e763ffffefdbf9e75dffffefd9f9ee5dffff",
    5642: "05efd7f9ee5dffffefd5f9ee5dffffefd3f9ee57ffffefd1f9ee5dffffefcff9ee5dffffefcdf9ee5dffffefcbf9ee5dffffefc9f9ee5dffffefc7f9ee5dffffefc5f9e757ffffeefff9e7d4f6",
    5659: "055dffffeefdf9e75dffffeefbf9e75dffffeef9f9e75dffffeef7f9e763ffffeef5f9df5dffffeef3f9df5dffffeef1f9df63ffffeeeff9df5dffffeeedf9df5dffffeeebf9df63ffffeee9f9df5dffffeee7f9df5dffffeee5f7f85dffffeee3f9ee5dffffeee1f8d257ffffeedff9ee5dffffeeddf8c757ffffeedbf9ee5dffffeed9f8d257ffffeed7f9fc5dffffeed5f8e75dffffeed3fac65dffffeed1fac65dffffeecffac65dffffeecdfac65dffffeecbfacd57ffffeec9facd5dffffeec7fac65dffffeec5fac65dffffedfff9fc5dffffedfdf9fc5dffffedfbf9fc5dffffedf9f9fc5dffffedf7f9ee5dffffedf5f9ee5dffffedf3f9e763ffffedf1f9e75dffffedeff9e75dffffededf9e75dffffedebf9e75dffffede9f9e757ffffede7f9f55dffffede5f9f557ffffede3f9fc5dffffede1f9fc57ffffeddffad35dffffedddfad357ffffeddbfad35dffffedd9fad35dffffedd7facd5dffffedd5facd5dffffedd3f9fc5dffffedd1f9fc5dffffedcff9f557ffffedcdf9f55dffffedcbf7f85dffffedc9f9e75dffffedc7f8c75dffffedc5f9ee5dffffecfff8d25dffffecfdf9f557ffffecfbf8d25dffffec",
    5663: "05f9f9fc5dffffecf7f8e75dffffecf5facd57ffffecf3facd5dffffecf1fad35dffffeceffad357ffffecedf8fa5dffffecebfad95dff0000000000000000000000000000000000000000dd73",
}

# Strip 0x05 type prefix, XOR all remaining bytes, skip trailing 2-byte CRC from last packet
# Strategy: identify which packets end with CRC (2 bytes of non-data)
# Actually each "group" (transaction) may have its own CRC
# For a CONVOY packet: 0x05 [type] [data...] [crc_2bytes]
# The CRC is on the BLE level, not the GATT level.
# Let's just concatenate all payload bytes (skip 0x05, XOR rest, no stripping)

print("\n\n== Feature 0x1f track data ==")
f1f_stream = b''
for frnum, hexdata in sorted(f1f_frames.items()):
    raw = bytes.fromhex(hexdata)
    assert raw[0] == 0x05
    # XOR bytes [1:]
    decoded = bytes(b ^ 0xff for b in raw[1:])
    f1f_stream += decoded

print(f"  Total stream: {len(f1f_stream)} bytes")

# Look at the structure: first bytes should be length
# data[0] | (data[1] << 8) = payload length
plen = f1f_stream[0] | (f1f_stream[1] << 8)
print(f"  Payload length header: {plen} = 0x{plen:04x}")
print(f"  First 20 bytes: {f1f_stream[:20].hex()}")
print(f"  Bytes [0-10]:")
for i in range(20):
    print(f"    [{i}] = 0x{f1f_stream[i]:02x} = {f1f_stream[i]}")

# Find where actual data starts (after length header = [2:])
stream_data = f1f_stream[2:]
print(f"\n  Stream data (after 2-byte length header) first 30 bytes:")
for i in range(30):
    print(f"    [{i}] = 0x{stream_data[i]:02x} = {stream_data[i]}")

# Now look for 5-byte record patterns
# Known structure from summary analysis of 0x1e:
# avg_pace=19:00 (19 min, 0 sec), max_pace=10:54 (10min,54sec)
# Duration=78s, 39 records
# Each record is 2s of activity

# Look for repeating patterns in stream_data
# Try identifying record boundaries
print(f"\n  Looking for patterns at various strides:")

# XOR back to see if there are readable patterns
# Actually the data IS decoded (XOR'd). Let me search for known values.

print("\n  Searching for distance=60, max_pace=654:")
for i in range(len(stream_data)-3):
    v8 = stream_data[i]
    v16le = stream_data[i] | (stream_data[i+1] << 8)
    v16be = (stream_data[i] << 8) | stream_data[i+1]
    if v8 == 60: print(f"    dist8 [{i}]={v8}")
    if v16le == 60: print(f"    dist16le [{i}]={v16le}")
    if v16le == 654: print(f"    maxpace16le [{i}]={v16le}")
    if v16be == 654: print(f"    maxpace16be [{i}]={v16be}")
    if v8 == 0x0a and stream_data[i+1] == 0x36: print(f"    bcd_10:54 [{i}]")

# The first non-zero block - get its exact position
print("\n  Looking for non-zero/non-padding start:")
for i in range(len(stream_data)):
    if stream_data[i] != 0 and stream_data[i] != 0xff:
        print(f"    First interesting byte at [{i}] = 0x{stream_data[i]:02x}")
        break

# Show a window of non-zero data
interesting_data = []
for i, b in enumerate(stream_data):
    if b != 0 and b != 0xff:
        interesting_data.append((i, b))

print(f"\n  Interesting (non-0, non-ff) bytes ({len(interesting_data)} total):")
for idx, (i, b) in enumerate(interesting_data):
    print(f"    [{i:4d}] = 0x{b:02x} = {b}")
    if idx > 200:
        print("    ...")
        break

# Now focus on feature 0x1f records - looking at consecutive blocks
# Find all non-zero runs in stream_data
runs = []
i = 0
while i < len(stream_data):
    if stream_data[i] != 0:
        j = i
        while j < len(stream_data) and stream_data[j] != 0:
            j += 1
        if j - i >= 3:
            runs.append((i, stream_data[i:j]))
        i = j
    else:
        i += 1

print(f"\n  Non-zero runs (potential records): {len(runs)}")
for rstart, rdata in runs[:20]:
    l = len(rdata)
    print(f"  Run [{rstart}] len={l}: {rdata.hex()}")
    # Try as multiple 5-byte records
    if l % 5 == 0:
        for k in range(0, l, 5):
            r = rdata[k:k+5]
            print(f"    5-byte rec {k//5}: {r.hex()} | bytes={list(r)}")
    # Try as 6-byte
    if l % 6 == 0:
        for k in range(0, l, 6):
            r = rdata[k:k+6]
            print(f"    6-byte rec {k//6}: {r.hex()} | bytes={list(r)}")

# Now decode the feature 0x20 track data
print("\n\n== Feature 0x20 track data (new session format) ==")
# This should be the SAME session data as 0x1f but for new sessions
# Frames 5733, 5737

f20_track_hex_5733 = "05ffd3e5f9d75dffffd3e3f9d75dffffd3e1f9df5dffffd3dff9df5dffffd3ddf9e75dffffd3dbf9e75dffffd3d9f8c75dffffd3d7f9ee5dffffd3d5f8d25dffffd3d3f9ee5dffffd3d1f8d25dffffd3cff9ee57ffffd3cdf8c75dffffd3cbf9f557ffffd3c9f8d25dffffd3c7f9f557ffffd3c5f9f55dffffd2fff9ee57ffffd2fdf9ee5dffffd2fbf9f557ffffd2f9f9f55dffffd2f7f9f55dffffd2f5f9f55dffffd2f3f9ee5dffffd2f1f9ee5dffffd2eff9e75dffffd2edf9e757ffffd2ebf8c75dffffd2e9f9f557ffffd2e7f8d25dffffd2e5f9f557ffffd2e3f8dd5dffffd2e1f9f55dffffd2dff8d25dffffd2ddf9fc5dffffd2dbf8e75dffffd2d9f8e75dffffd2d7facd57ffffd2d5f8e75dffffd2d3f9fc57ffffd2d1f8dd5dffffd2cff9f557ffffd2cdf8dd5dffffd2cbf9f55dffffd2c9f8c75dffffd2c7f9f55dffffd2c5f9f55dffffd1fff9e75dffffd1fdf9e75dffffd1fbf9ee5dffffd1f9f9ee5dffffd1f7f9f55dffffd1f5f9f55dffffd1f3f8dd57ffffd1f1f9fc5dffffd1eff8d25dffffd1edf9ee5dffffd1ebf8d25dffffd1e9f9ee5dffffd1e7f8c75dffffd1e5f9e757ffffd1e3f7f85dffffd1e1f9"
f20_track_hex_5737 = "05df57ffffd1dff9df5dffffd1ddf9df5dff"

# Combine and decode (skip 0x05, XOR rest)
def decode_convoy(hexdata):
    raw = bytes.fromhex(hexdata)
    assert raw[0] == 0x05
    return bytes(b ^ 0xff for b in raw[1:])

f20_track_combined = decode_convoy(f20_track_hex_5733) + decode_convoy(f20_track_hex_5737)
print(f"  f20 track combined: {len(f20_track_combined)} bytes")

# Strip padding (0x00 decoded from raw 0xff)
# Find non-zero runs
f20_runs = []
i = 0
while i < len(f20_track_combined):
    if f20_track_combined[i] != 0:
        j = i
        while j < len(f20_track_combined) and f20_track_combined[j] != 0:
            j += 1
        if j - i >= 3:
            f20_runs.append((i, f20_track_combined[i:j]))
        i = j
    else:
        i += 1

print(f"  Non-zero runs in f20 track: {len(f20_runs)}")
for rstart, rdata in f20_runs:
    l = len(rdata)
    print(f"  Run [{rstart}] len={l}: {rdata[:40].hex()}{'...' if l > 40 else ''}")

# The track data should have 39 records of some size
# Let's try multiple strides
all_track = b''.join(r for _, r in f20_runs)
print(f"\n  Combined non-zero track bytes: {len(all_track)}")
print(f"  Hex: {all_track.hex()}")

# 39 records * ? bytes = total
print(f"\n  Possible record sizes: {len(all_track)} bytes / 39 records = {len(all_track)/39:.1f}")
print(f"  Possible record sizes: {len(all_track)} bytes / 5 = {len(all_track)/5:.1f}")
print(f"  Possible record sizes: {len(all_track)} bytes / 6 = {len(all_track)/6:.1f}")

# Show as 5-byte records
if len(all_track) % 5 == 0:
    print(f"\n  As 5-byte records ({len(all_track)//5} records):")
    for k in range(0, len(all_track), 5):
        r = all_track[k:k+5]
        print(f"    rec {k//5:2d}: {r.hex()} | {list(r)}")

# Show as 6-byte records
if len(all_track) % 6 == 0:
    print(f"\n  As 6-byte records ({len(all_track)//6} records):")
    for k in range(0, len(all_track), 6):
        r = all_track[k:k+6]
        print(f"    rec {k//6:2d}: {r.hex()} | {list(r)}")

# Show as 7-byte records
if len(all_track) % 7 == 0:
    print(f"\n  As 7-byte records ({len(all_track)//7} records):")
    for k in range(0, len(all_track), 7):
        r = all_track[k:k+7]
        print(f"    rec {k//7:2d}: {r.hex()} | {list(r)}")

# Now let's also look at feature 0x1f track to see if there's a pace format
# that could help us find max_pace=654
print("\n\n== Searching for max_pace 654 in 0x1f track stream ==")
# We know max_pace=654 s/km = 10 min 54 sec
# XOR'd: if raw byte = pace_value -> decoded = 0xff ^ pace_value
# Wait, let me check: the code says ~data[i] which is XOR 0xff
# So decoded[i] = raw[i] ^ 0xff
# If decoded[i] = 0x0a (10), then raw = 0xf5
# If decoded[i] = 0x36 (54), then raw = 0xc9
# Pattern 0xf5 0xc9 in raw bytes would be max pace 10:54 in BCD!

print("  Looking for raw pattern 0xf5 0xc9 (= BCD 10:54 after XOR) in 0x1f raw data:")
for frnum, hexdata in sorted(f1f_frames.items()):
    raw = bytes.fromhex(hexdata)
    for i in range(len(raw)-1):
        if raw[i] == 0xf5 and raw[i+1] == 0xc9:
            print(f"    Found at frame {frnum}, byte {i}: ...{raw[max(0,i-3):i+5].hex()}...")

# Also search all 0x1f decoded stream
print("  In 0x1f decoded stream (looking for 0x0a 0x36):")
for i in range(len(f1f_stream)-1):
    if f1f_stream[i] == 0x0a and f1f_stream[i+1] == 0x36:
        print(f"    Found at [{i}]: {f1f_stream[max(0,i-3):i+6].hex()}")

# For 0x1e:
print("  In 0x1e decoded (looking for 0x0a 0x36):")
for i in range(len(f1e_dec)-1):
    if f1e_dec[i] == 0x0a and f1e_dec[i+1] == 0x36:
        print(f"    Found at [{i}]: {f1e_dec[max(0,i-3):i+6].hex()}")

# Also look for 0xf5 0xc9 pattern in 0x1e raw
print("  In 0x1e raw (0xf5 0xc9 = BCD 10:54 after XOR):")
f1e_raw_again = bytes.fromhex(f1e_hex)
for i in range(len(f1e_raw_again)-1):
    if f1e_raw_again[i] == 0xf5 and f1e_raw_again[i+1] == 0xc9:
        print(f"    Found at [{i}]: raw ...{f1e_raw_again[max(0,i-3):i+5].hex()}... | decoded: {bytes(b^0xff for b in f1e_raw_again[max(0,i-3):i+5]).hex()}")

# Now check 0x20 header for 0xf5 0xc9
print("  In 0x20 header raw (0xf5 0xc9):")
f20_hdr_hex = "0501ecffbdbcff00000000ffffffffffff01b3ea73c2fffee9fffeedecfffcffffff95ff"
f20_hdr_raw = bytes.fromhex(f20_hdr_hex)
for i in range(len(f20_hdr_raw)-1):
    if f20_hdr_raw[i] == 0xf5 and f20_hdr_raw[i+1] == 0xc9:
        print(f"    Found at [{i}]: raw ...{f20_hdr_raw[max(0,i-3):i+6].hex()}... decoded: {bytes(b^0xff for b in f20_hdr_raw[max(0,i-3):i+6]).hex()}")

# Look for any place in 0x20 header that might encode 654 or 60
print("\n  All non-trivial values in 0x20 header decoded:")
f20_hdr_dec = bytes(b ^ 0xff for b in f20_hdr_raw[1:])  # skip type byte 05
for i, b in enumerate(f20_hdr_dec):
    if 1 < b < 250:
        print(f"    [{i}] = {b} (0x{b:02x})")

# Let's also check: distance might be encoded differently
# 60m = 60, if unit is meters, stored as uint16 LE: 0x3c 0x00
# 60m = 0.06km * 1000 = 60
# Could also be stored as centimeters: 6000 = 0x1770
# Or as 10m units: 6 in 10m units
# Or as decimeters: 600 = 0x0258

print("\n  Checking 0x1e for all distance candidates:")
for i in range(len(f1e_dec)-3):
    v8 = f1e_dec[i]
    v16le = f1e_dec[i] | (f1e_dec[i+1] << 8)
    v16be = (f1e_dec[i] << 8) | f1e_dec[i+1]
    for target, label in [(6, "6(10m)"), (60, "60m"), (600, "600dm"), (6000, "6000cm")]:
        if v8 == target and v8 < 200:
            print(f"    dist8  [{i}]={target} ({label})")
        if v16le == target:
            print(f"    dist16le [{i}]={target} ({label})")
        if v16be == target:
            print(f"    dist16be [{i}]={target} ({label})")

print("\n  Checking 0x20 header decoded for distance candidates:")
for i in range(len(f20_hdr_dec)-3):
    v8 = f20_hdr_dec[i]
    v16le = f20_hdr_dec[i] | (f20_hdr_dec[i+1] << 8)
    v16be = (f20_hdr_dec[i] << 8) | f20_hdr_dec[i+1]
    for target, label in [(6, "6(10m)"), (60, "60m"), (600, "600dm"), (6000, "6000cm")]:
        if v8 == target and v8 < 200:
            print(f"    dist8  [{i}]={target} ({label})")
        if v16le == target:
            print(f"    dist16le [{i}]={target} ({label})")
        if v16be == target:
            print(f"    dist16be [{i}]={target} ({label})")

print("\n\nDone.")
