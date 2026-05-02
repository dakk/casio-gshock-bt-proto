#!/usr/bin/env python3
"""Full decoder for Casio GBD-200 sport activity BLE packets from btsnoop_hci_2.log"""

# Ground truth for the 2026-04-29 15:23 local (13:23 UTC) session:
# Distance: 60 meters (0.06 km)
# Duration: 78 seconds (1'18'')
# Avg pace: 1140 s/km (19'00''/km)
# Max pace: 654 s/km (10'54''/km)
# Calories: 3 kcal
# Cadence: 106 fpm
# Records: 39 (78s / 2s per record)

# XOR helper
def xor_all(data):
    return bytes(b ^ 0xff for b in data)

def xor_skip_first(data):
    # Skip the first byte (type 0x05), XOR the rest
    return bytes([data[0]] + [b ^ 0xff for b in data[1:]])

# Feature 0x1e summary packet (from frame 5483)
f1e_raw = bytes.fromhex(
    "0500ffff0100000000000000040000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000f8ffecffeefeffffd8ffffffecfffffffefffffff7d9dffbd6ecdc"
    "b8d9dffbd6ecdafaff5fb8ffff3fb4ffb3ea73c2fffeedecfffcffffff95ffffffffffffffffffffffffff"
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb27"
)

# Strip the last 2 bytes (CRC) from the CONVOY packet
# The CONVOY format: [type=05][len_lo][len_hi][payload][crc_2bytes]
# But actually from the data request pattern, the whole packet is:
# 05 [2-byte payload len XOR] [payload XOR] [2-byte CRC]
# Wait - let me re-examine. The XOR inversion applies to ALL bytes.
# After XOR:
# 05 -> fa (type byte stays as reference, but let's XOR all)

# Actually the format from FetchStepCountDataOperation:
# for(int i=0; i<data.length; i++) data[i] = (byte)(~data[i]);
# So ALL bytes are XOR'd with 0xFF

# Feature 0x1e data from frame 5483 (removing trailing CRC bytes eb27):
f1e_hex = "0500ffff0100000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f8ffecffeefeffffd8ffffffecfffffffefffffff7d9dffbd6ecdcb8d9dffbd6ecdafaff5fb8ffff3fb4ffb3ea73c2fffeedecfffcffffff95ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

f1e_raw = bytes.fromhex(f1e_hex)
# Remove last 2 bytes (CRC eb27 not in this hex)
f1e_dec = xor_all(f1e_raw)
print(f"Feature 0x1e decoded ({len(f1e_dec)} bytes):")
print(f"  [0-1] payload_len = {f1e_dec[0]:02x} {f1e_dec[1]:02x} = {f1e_dec[0] | (f1e_dec[1]<<8)}")

# Print all non-zero bytes with indices
print("  Non-zero bytes:")
for i, b in enumerate(f1e_dec):
    if b != 0:
        print(f"    [{i}] = 0x{b:02x} = {b}")

print()

# Known positions from previous analysis:
# [129] = 0x13 = 19 (avg pace min)
# [130] = 0x00 (avg pace sec)
# [135] = 0x27 = 39 (record count)
# [148-154] = start time BCD: 26 20 04 29 13 23 47
# [155-161] = end time BCD: 26 20 04 29 13 25 05
# [167-168] = c0 4b (ptr to feature 0x20)
# [179] = 0x03 (calories)
# [183] = 0x6a (cadence=106)
# Need: distance=60m, max_pace=654

# Look for 60 (0x3c) and related values
print("Looking for distance=60 in 0x1e:")
for i in range(len(f1e_dec)-3):
    v8 = f1e_dec[i]
    v16 = f1e_dec[i] | (f1e_dec[i+1] << 8)
    v16b = f1e_dec[i+1] | (f1e_dec[i+2] << 8)
    if v8 == 60:
        print(f"  8-bit match at [{i}] = {v8}")
    if v16 == 60:
        print(f"  16-bit LE match at [{i}-{i+1}] = {v16}")

print("Looking for max_pace=654 in 0x1e:")
for i in range(len(f1e_dec)-3):
    v16 = f1e_dec[i] | (f1e_dec[i+1] << 8)
    if v16 == 654:
        print(f"  16-bit LE match at [{i}-{i+1}] = {v16}")
    # BCD: 10min 54sec = 0x10 0x54
    if f1e_dec[i] == 0x10 and f1e_dec[i+1] == 0x54:
        print(f"  BCD min:sec match at [{i}-{i+1}]")

print()

# Feature 0x20 header packet (frame 5691)
f20_hex = "0501ecffbdbcff00000000ffffffffffff01b3ea73c2fffee9fffeedecfffcffffff95ff" + "00"*432
f20_raw = bytes.fromhex(f20_hex[2:])  # skip type byte 05
# Wait - the type byte 05 should also be XOR'd based on FetchStepCountDataOperation
# The code does: for(int i=0; i<data.length; i++) data[i] = (byte)(~data[i]);
# So it XORs ALL bytes including the first one

f20_full_hex = "0501ecffbdbcff00000000ffffffffffff01b3ea73c2fffee9fffeedecfffcffffff95ff"
f20_raw_full = bytes.fromhex(f20_full_hex)
f20_dec_full = xor_all(f20_raw_full)
print(f"Feature 0x20 header decoded ({len(f20_dec_full)} bytes):")
print(f"  [0] type byte after XOR = 0x{f20_dec_full[0]:02x}")
for i, b in enumerate(f20_dec_full):
    if b != 0:
        print(f"    [{i}] = 0x{b:02x} = {b}")

print()
print("Looking for distance=60 in 0x20 header:")
for i in range(len(f20_dec_full)-3):
    v8 = f20_dec_full[i]
    v16 = f20_dec_full[i] | (f20_dec_full[i+1] << 8)
    if v8 == 60:
        print(f"  8-bit match at [{i}] = {v8}")
    if v16 == 60:
        print(f"  16-bit LE match at [{i}-{i+1}]")

print("Looking for max_pace=654 in 0x20 header:")
for i in range(len(f20_dec_full)-3):
    v16 = f20_dec_full[i] | (f20_dec_full[i+1] << 8)
    if v16 == 654:
        print(f"  16-bit LE match at [{i}-{i+1}]")
    if f20_dec_full[i] == 0x10 and f20_dec_full[i+1] == 0x54:
        print(f"  BCD min:sec match at [{i}-{i+1}]")

print()

# Now decode feature 0x1f track data (old session format) from frames 5511-5663
# These frames have actual track data for the same session

f1f_packets = [
    "0500eefebdfeff00000000000000000000fffffdfffffffffffffbfffffffffffff9fffffffffffff7fffffffffffff5ffff9ffffffff3ffff9ffffffff1ffffabffffffefffffabffffffedffffb7ffffffebffffb1ffffffe9ffffa5ffffffe7ffff93ffffffe5ffff8dffffffe3ffff7bffffffe1ffff7bffffffdfffff87ffffffddffff8dffffffdbffff8dffffffd9ffff93ffffffd7ffff93ffffffd5ffff87ffffffd3ffff87ffffffd1ffff87ffffffcfffff81ffffffcdffff87ffffffcbf5c993ffffffc9f5c999ffffffc7f5c999ffffffc5f5c99ffffffefff5c999fffffefdf5c999fffffefbf5c993fffffef9f5c993fffffef7f5c993fffffef5f5c999fffffef3f3f193fffffef1f3f193fffffeeff3f193fffffeedf3f193ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001288",
    "05000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0500000000000000fffbcbf9e763fffffbc9f9ee5dfffffbc7f9ee63fffffbc5f9ee5dfffffafff9ee5dfffffafdf9ee5dfffffafbf9ee63fffffaf9f9e75dfffffaf7f9e763fffffaf5f9e763fffffaf3f9e75dfffffaf1f9e75dfffffaeff9e763fffffaedf9ee5dfffffaebf9ee5dfffffae9f9f563fffffae7f9f563fffffae5f9fc5dfffffae3f9fc63fffffae1f9fc5dfffffadff9fc5dfffffaddf9f55dfffffadbf9f563fffffad9f9ee5dfffffad7f9ee63fffffad5f9e763fffffad3f9e75dfffffad1f9df5dfffffacff9df63fffffacdf9df5dfffffacbf9df5dfffffac9f9e75dfffffac7f9e75dfffffac5f9ee5dfffff9fff9ee5dfffff9fdf9ee5dfffff9fbf9ee63fffff9f9f9f55dfffff9f7f9f55dfffff9f5f9ee63fffff9f3f9ee5dfffff9f1f9e75dfffff9eff9e75dfffff9edf9df5dfffff9ebf9df5dfffff9e9f9df5dfffff9e7f9df5dfffff9e5f9d75dfffff9e3f9d75dfffff9e1f9d75dfffff9dff9d75dfffff9ddf9df5dfffff9dbf9df5dfffff9d9f9ee5dfffff9d7f9ee5dfffff9d5f9fc63fffff9d3f9fc5dfffff9d1f9fc63fffff9cff9fc63fffff9cdfacd5dfffff9cbfacd5dfffff9c9fa",
    "05d35dfffff9c7fad35dfffff9c5facd5dfffff8fffacd63fffff8fdf9fc5dfffff8fbf9fc63fffff8f9fac65dfffff8f7fac65dfffff8f5f9fc5dfffff8f3f9fc5dfffff8f1f9ee5dffff1d39",
    "05f8eff9ee63fffff8edf9e75dfffff8ebf9e75dfffff8e9f9f563fffff8e7f9f55dfffff8e5f9f55dfffff8e3f9f563fffff8e1f9f55dfffff8dff9f55dfffff8ddf9f55dfffff8dbf9f55dfffff8d9f9f557fffff8d7f9f55dfffff8d5f9e75dfffff8d3f9e75dfffff8d1f7f85dfffff8cff9ee63fffff8cdf8c75dfffff8cbf9ee5dfffff8c9f8d25dfffff8c7f9ee5dfffff8c5f8d25dfffff7fff9f55dfffff7fdf8dd5dfffff7fbf9fc5dfffff7f9f9fc5dfffff7f7f9fc5dfffff7f5f9fc5dfffff7f3fac65dfffff7f1fac663fffff7effacd5dfffff7edfacd5dfffff7ebfac663fffff7e9fac65dfffff7e7f9fc5dfffff7e5f9fc63fffff7e3f9f55dfffff7e1f9f55dfffff7dff9e75dfffff7ddf9e75dfffff7dbf9df57fffff7d9f9df5dfffff7d7f9df5dfffff7d5f9df5dfffff7d3f9df5dfffff7d1f9df63fffff7cff9d75dfffff7cdf9d75dfffff7cbf9e763fffff7c9f9e75dfffff7c7f9ee5dfffff7c5f9ee5dfffff6fff9ee5dfffff6fdf9ee5dfffff6fbf9f55dfffff6f9f9f55dfffff6f7f9f563fffff6f5f9f55dfffff6f3f9e75dfffff6f1f9e75dfffff6eff9df5dfffff6edf9df57fffff6ebf9e7",
    "055dfffff6e9f9e75dfffff6e7f9df5dfffff6e5f9df5dfffff6e3f9df5dfffff6e1f9df5dfffff6dff9df5dfffff6ddf9df5dfffff6dbf9df5dfffff6d9f9df5dfffff6d7f9d75dfffff68ca8",
    "05d5f9d75dfffff6d3f9df5dfffff6d1f9df5dfffff6cff9e763fffff6cdf9e75dfffff6cbf9e75dfffff6c9f9e763fffff6c7f9e75dfffff6c5f9e75dfffff5fff9e763fffff5fdf9e75dfffff5fbf9e75dfffff5f9f9e75dfffff5f7f9ee5dfffff5f5f9ee5dfffff5f3f9ee5dfffff5f1f9ee5dfffff5eff9ee5dfffff5edf9ee5dfffff5ebf9ee57fffff5e9f9ee5dfffff5e7f9ee57fffff5e5f9ee5dfffff5e3f9df57fffff5e1f9df5dfffff5dff9df57fffff5ddf9df5dfffff5dbf9e75dfffff5d9f9e75dfffff5d7f9ee5dfffff5d5f9ee5dfffff5d3f9e75dfffff5d1f9e75dfffff5cff9e75dfffff5cdf9e75dfffff5cbf9ee5dfffff5c9f9ee5dfffff5c7f9ee57fffff5c5f9ee5dfffff4fff9ee57fffff4fdf9ee5dfffff4fbf9ee5dfffff4f9f9ee5dfffff4f7f9f55dfffff4f5f9f55dfffff4f3f9f55dfffff4f1f9f557fffff4eff9ee5dfffff4edf9ee57fffff4ebf9f55dfffff4e9f9f55dfffff4e7f9fc5dfffff4e5f9fc5dfffff4e3f9f55dfffff4e1f9f55dfffff4dff9ee5dfffff4ddf9ee5dfffff4dbf9f55dfffff4d9f9f55dfffff4d7f9ee5dfffff4d5f9ee57fffff4d3f9ee5dfffff4d1f9ee5d",
    "05fffff4cff9ee5dfffff4cdf9ee5dfffff4cbf8d263fffff4c9f9ee63fffff4c7f8c75dfffff4c5f9ee63fffff3fff8c75dfffff3fdf9ee5dfffff3fbf8c757fffff3f9f9e75dfffff3f7c257",
    "05f8c757fffff3f5f9e75dfffff3f3f9e757fffff3f1f9e75dfffff3eff9e757fffff3edf9e75dfffff3ebf9e75dfffff3e9f9df5dfffff3e7f9df5dfffff3e5f9e75dfffff3e3f9e75dfffff3e1f9ee57fffff3dff9ee5dfffff3ddf8d257fffff3dbf9fc5dfffff3d9f8dd5dfffff3d7f9f55dfffff3d5f8dd5dfffff3d3f9fc63fffff3d1f8dd5dfffff3cff9fc5dfffff3cdf8dd63fffff3cbf8dd5dfffff3c9f9fc5dfffff3c7f8d263fffff3c5f9ee5dfffff2fff9ee5dfffff2fdf9ee5dfffff2fbf9fc5dfffff2f9faf85dfffff2f7f9f55dfffff2f5fafc5dfffff2f3fafc63fffff2f1f9fc5dfffff2effbc55dfffff2edfacd5dfffff2ebfade5dfffff2e9fade57fffff2e7fad95dfffff2e5f9cf57fffff2e3fade5dfffff2e1f9c757fffff2dffade5dfffff2ddfade57fffff2dbfad95dfffff2d9fad95dfffff2d7fac65dfffff2d5fac65dfffff2d3fac65dfffff2d1fac65dfffff2cffac65dfffff2cdfafc5dfffff2cbf9f55dfffff2c9fafc5dfffff2c7f9fc5dfffff2c5faf85dfffff1fff9fc5dfffff1fdfafc5dfffff1fbf9f563fffff1f9fafc5dfffff1f7f9fc5dfffff1f5fad363fffff1f3fad363ff",
    "05fff1f1fad35dfffff1effad363fffff1edf9c763fffff1ebfad95dfffff1e9f9c75dfffff1e7fad363fffff1e5f8f15dfffff1e3fac65dfffff1e1f8d263fffff1dff9fc63fffff1ddf8e3ce",
    "05d25dfffff1dbf9ee63fffff1d9f9ee5dfffff1d7f9e75dfffff1d5f9e75dfffff1d3f9e763fffff1d1f9e75dfffff1cff9e763fffff1cdf9e763fffff1cbf9d75dfffff1c9f9d75dfffff1c7f9d763fffff1c5f9d75dfffff0fff9d75dfffff0fdf9d763fffff0fbf9e75dfffff0f9f9e75dfffff0f7f9e763fffff0f5f9e75dfffff0f3f9e75dfffff0f1f9e763fffff0eff9ee5dfffff0edf9ee5dfffff0ebf9fc5dfffff0e9f9fc5dfffff0e7f9ee5dfffff0e5f9ee5dfffff0e3f9fc5dfffff0e1f9fc63fffff0dff9fc5dfffff0ddf9fc5dfffff0dbf9fc63fffff0d9f9fc5dfffff0d7f9fc5dfffff0d5f9fc63fffff0d3f9fc5dfffff0d1f9fc5dfffff0cff9f55dfffff0cdf9f55dfffff0cbf9f55dfffff0c9f9f55dfffff0c7f8d25dfffff0c5f9fc5dffffeffff8d25dffffeffdf9f55dffffeffbf8dd5dffffeff9f9fc5dffffeff7f8dd63ffffeff5f9f55dffffeff3f8dd5dffffeff1f9f563ffffefeff9f55dffffefedf9e75dffffefebf9e763ffffefe9f9df5dffffefe7f9df5dffffefe5f9d763ffffefe3f9d763ffffefe1f9df5dffffefdff9df63ffffefddf9e763ffffefdbf9e75dffffefd9f9ee5dffff",
    "05efd7f9ee5dffffefd5f9ee5dffffefd3f9ee57ffffefd1f9ee5dffffefcff9ee5dffffefcdf9ee5dffffefcbf9ee5dffffefc9f9ee5dffffefc7f9ee5dffffefc5f9e757ffffeefff9e7d4f6",
    "055dffffeefdf9e75dffffeefbf9e75dffffeef9f9e75dffffeef7f9e763ffffeef5f9df5dffffeef3f9df5dffffeef1f9df63ffffeeeff9df5dffffeeedf9df5dffffeeebf9df63ffffeee9f9df5dffffeee7f9df5dffffeee5f7f85dffffeee3f9ee5dffffeee1f8d257ffffeedff9ee5dffffeeddf8c757ffffeedbf9ee5dffffeed9f8d257ffffeed7f9fc5dffffeed5f8e75dffffeed3fac65dffffeed1fac65dffffeecffac65dffffeecdfac65dffffeecbfacd57ffffeec9facd5dffffeec7fac65dffffeec5fac65dffffedfff9fc5dffffedfdf9fc5dffffedfbf9fc5dffffedf9f9fc5dffffedf7f9ee5dffffedf5f9ee5dffffedf3f9e763ffffedf1f9e75dffffedeff9e75dffffededf9e75dffffedebf9e75dffffede9f9e757ffffede7f9f55dffffede5f9f557ffffede3f9fc5dffffede1f9fc57ffffeddffad35dffffedddfad357ffffeddbfad35dffffedd9fad35dffffedd7facd5dffffedd5facd5dffffedd3f9fc5dffffedd1f9fc5dffffedcff9f557ffffedcdf9f55dffffedcbf7f85dffffedc9f9e75dffffedc7f8c75dffffedc5f9ee5dffffecfff8d25dffffecfdf9f557ffffecfbf8d25dffffec",
    "05f9f9fc5dffffecf7f8e75dffffecf5facd57ffffecf3facd5dffffecf1fad35dffffeceffad357ffffecedf8fa5dffffecebfad95dff0000000000000000000000000000000000000000dd73",
]

# Concatenate all 0x1f packet data (exclude type byte and strip CRC from last packet)
# Remove 2-byte CRC from last packet of each "group"
# Actually let's concatenate all raw bytes and XOR invert everything

f1f_combined = b''
for pkt in f1f_packets:
    raw = bytes.fromhex(pkt)
    # XOR all bytes
    decoded = xor_all(raw)
    f1f_combined += decoded

print(f"Feature 0x1f combined decoded data ({len(f1f_combined)} bytes)")

# The first packet has the length header
# After XOR: type byte becomes 0xfa, length bytes, payload
# Wait, the first raw byte 0x05 XOR 0xff = 0xfa
# The second byte 0x00 XOR 0xff = 0xff
# But we expect data here. Let me recheck.

# Actually wait - the type byte 0x05 is the CONVOY packet type indicator for DATA packets
# But after XOR it would become 0xfa which doesn't make sense as a feature ID
#
# Looking at FetchStepCountDataOperation.java:
# } else if(characteristicUUID.equals(CasioConstants.CASIO_CONVOY_CHARACTERISTIC_UUID)) {
#     for(int i=0; i<data.length; i++) data[i] = (byte)(~data[i]);
#     int payloadLength = ((data[0] & 0xff) | ((data[1] & 0xff) << 8));
#
# So the length is at positions [0] and [1] AFTER XOR inversion.
# First raw byte 0x05 -> after XOR 0xfa (252) - this doesn't look like length
# But second raw byte 0x00 -> after XOR 0xff (255)
# Length = 0xfa | (0xff << 8) = 0xfffa = 65530 which is wrong

# Wait, maybe the type byte 0x05 is NOT part of the GATT characteristic value!
# Maybe it's a CONVOY packet indicator byte prepended separately.
# Let me look at FetchStepCountDataOperation more carefully.
# The for loop starts at i=0, so it DOES XOR all bytes.
# Then payloadLength = data[0] | (data[1] << 8)
# So the first two bytes after XOR are the length.
#
# For the step count data, the raw would be:
# ~ of (actual_len_lo | actual_len_hi | actual_data)
#
# For convoy data type 0x05, what's the format?
# 0x05 is the data type indicator.
# Maybe for the 0x04 step count type, the raw packet starts with 0xfe 0xff (= ~0x01 ~0x00)
# meaning actual payload length = 1?
#
# Actually wait - let me look at how the step count data looks after XOR:
# "int payloadLength = ((data[0] & 0xff) | ((data[1] & 0xff) << 8));"
#
# The step count CONVOY packet: the raw bytes would be XOR of the actual data
# If payload_length = 18 (for example), then raw = ~18, ~0 = 0xed 0xff
#
# For feature 0x1f, first raw packet starts: 0500eefebdfeff...
# After XOR: fa ff 11 01 42 01 00 ...
# [0] = 0xfa, [1] = 0xff -> length = 0xfa | (0xff << 8) = 0xfffa ??
# That seems wrong.

# UNLESS the type byte 0x05 is stripped before passing to the handler
# and the length bytes come right after.

# Let me look at what the step count packet looks like after stripping type
# For step count feature (0x04), looking at old log or known pattern...
# The step count raw might be: fe ff <data> where ~0xfe=0x01, ~0xff=0x00 -> length=1
# But the step count has much more data...

# Let me reconsider. Maybe:
# - Byte 0 is the feature/convoy type indicator (e.g., 0x05)
# - It is NOT included in the XOR inversion start
# - Bytes 1+ are XOR'd

# But the code clearly does: for(int i=0; i<data.length; i++) data[i] = (byte)(~data[i]);
# Starting from i=0.

# Let me try ONLY XOR-ing bytes starting from index 1 (skip type byte):
# 0500eefebdfeff...
# type = 0x05 (left as is)
# byte[1] = 0x00 XOR 0xff = 0xff
# byte[2] = 0xee XOR 0xff = 0x11
# byte[3] = 0xfe XOR 0xff = 0x01
# -> length = 0xff | (0x11 << 8) = 0x11ff = 4607 bytes -- also wrong

# OK let me try: the type byte IS 0x05, it stays.
# The next 2 bytes are the raw (XOR'd) length:
# For 0x1f: 0x00, 0xee -> XOR -> 0xff, 0x11 -> length = 0xff | (0x11 << 8) = 4607 -- nope

# Hmm. Let me try: raw data is NOT XOR'd for the length bytes.
# What if the packet format is:
# [0]: feature type (0x05 for data)  -- NOT XOR'd
# [1-2]: XOR'd payload length
# [3+]: XOR'd payload

# With 0x1f raw: 05 00 ee fe bd fe ff ...
# Skip type: [1]=0x00, [2]=0xee -> length bytes XOR -> 0xff, 0x11 -> still wrong

# Wait! Maybe for CONVOY type 0x05, the structure is different from step count (0x04).
# Maybe 0x05 data doesn't have the length header at all!
# The step count operation handles TWO different characteristics differently.

# Actually, looking at the raw data format again...
# For step count, the CONVOY packet starts with: (some raw) that after XOR gives payloadLength
# The step count CONVOY raw data was (from memory, not looking at the log):
# "~(length_lo) ~(length_hi) ~(data0) ~(data1) ..."
#
# But for SPORT data (type 0x05), the raw starts with 0x05 which after XOR = 0xfa
# This 0xfa could be part of the length: length_lo = 0xfa
# If second byte is part of length: 0x00 -> 0xff -> length = 0xfa | (0xff << 8) = 0xfffa

# I think the key insight might be: 0x05 is NOT a packet type prefix in the GATT value!
# Instead, the raw GATT value IS the XOR'd data directly.
# The 0x05 appears because ~0xfa = 0x05 and 0xfa is NOT a length byte - it's something else.

# ALTERNATIVE: maybe the packets that start with 0x05 are CONVOY packets of type 5
# and the step count data uses a different (type 4?) format where the entire packet is XOR.
# For sport data (type 5), maybe only PART is XOR'd.

# Let me look more carefully at the raw data patterns.
# For 0x1f, the first raw packet: 0500eefebdfeff...
# If we DON'T XOR the first 4 bytes but DO XOR the rest...
# [0]=0x05 (type), [1]=0x00, [2]=0xee, [3]=0xfe -> header, then data

# Actually I think the format might be:
# [0] = convoy subtype (0x05 = feature data packet)
# [1-2] = XOR'd payload length (raw bytes)
# [3+] = XOR'd payload

# For 0x1f first packet: type=0x05, len_bytes = 0x00 0xee, data = 0xbd 0xfe 0xff ...
# XOR len_bytes: 0xff, 0x11 -> length = 0x11ff = 4607 -- still wrong

# WAIT. Let me look at this differently.
# What if the length IS correct at 0xfffa = 65530 when counting ALL the XOR'd bytes?
# And the actual meaningful data is just the non-zero parts?

# OR: maybe only the FIRST byte 0x05 is stripped (it's a packet type indicator)
# and the remaining bytes [1:] form the XOR'd data stream
#
# For 0x1f: skip 0x05, remaining: 00 ee fe bd fe ff ...
# XOR remaining: ff 11 01 42 01 00 ...
# length = 0xff | (0x11 << 8) = 0x11ff = 4607 bytes
# Wait but the actual data we saw from the summary says 39 records * 6 bytes/record = 234 bytes?

# Let me try a completely different approach: just look at the non-zero decoded bytes
# to understand the structure

print("\nFeature 0x1f analysis (skipping type byte 0x05, XOR rest):")
f1f_raw_all = b''
for pkt in f1f_packets:
    f1f_raw_all += bytes.fromhex(pkt)

# Skip type byte from first packet, XOR rest
# Actually since all packets are concatenated, we should:
# 1. Collect all packets' payloads (skip the leading 0x05 of EACH packet)
# 2. XOR all of them
# 3. That gives us the combined data stream

f1f_stream = b''
for pkt in f1f_packets:
    raw = bytes.fromhex(pkt)
    # Option A: skip first byte (0x05), XOR rest
    stream_part = bytes(b ^ 0xff for b in raw[1:])
    f1f_stream += stream_part

print(f"  Stream length (skip type, XOR rest): {len(f1f_stream)} bytes")

# First bytes:
for i in range(20):
    print(f"  [{i}] = 0x{f1f_stream[i]:02x} = {f1f_stream[i]}")

print("\n  Non-zero bytes in stream:")
nonzero_count = 0
for i, b in enumerate(f1f_stream):
    if b != 0:
        print(f"    [{i}] = 0x{b:02x} = {b}")
        nonzero_count += 1
        if nonzero_count > 200:
            print("    ... (truncated)")
            break

print(f"\n  Looking for 5-byte records in stream:")
# Try to find repeating patterns by looking for 5-byte blocks
# Known: avg_pace=19, max_pace=10:54 (654 s/km), cadence=106
# 654 = 0x028e
# 60 m distance

print("\n  Searching for distance=60 (various encodings):")
for i in range(len(f1f_stream)-3):
    v8 = f1f_stream[i]
    v16le = f1f_stream[i] | (f1f_stream[i+1] << 8)
    if v8 == 60:
        print(f"    8-bit at [{i}]: {v8}")
    if v16le == 60:
        print(f"    16-bit LE at [{i}]: {v16le}")

print("\n  Searching for max_pace=654 s/km:")
for i in range(len(f1f_stream)-3):
    v16le = f1f_stream[i] | (f1f_stream[i+1] << 8)
    if v16le == 654:
        print(f"    16-bit LE at [{i}]: {v16le}")
    if f1f_stream[i] == 0x10 and f1f_stream[i+1] == 0x54:
        print(f"    BCD min:sec at [{i}]")

print("\n  Searching for max_pace=654 in different forms:")
# 654/2 = 327 = 0x147 (if stored as 2s intervals)
# 654 as BCD = 6 5 4 ...
# 654 as big-endian: 0x02 0x8e
for i in range(len(f1f_stream)-3):
    v8 = f1f_stream[i]
    v16le = f1f_stream[i] | (f1f_stream[i+1] << 8)
    v16be = (f1f_stream[i] << 8) | f1f_stream[i+1]
    if v16be == 654:
        print(f"    16-bit BE at [{i}]: {v16be}")
    if v8 == 0x0a and f1f_stream[i+1] == 0x36:  # BCD 10:54
        print(f"    BCD 0x0a/0x36 (10:54 in BCD-ish) at [{i}]")

# Let's look at the structure of what's non-zero in stream
# and try to understand 5-byte vs 7-byte records
print("\n  Finding 5-byte patterns (all non-zero consecutive blocks):")
i = 0
record_starts = []
while i < len(f1f_stream) - 4:
    if f1f_stream[i] != 0:
        # find end of non-zero run
        j = i
        while j < len(f1f_stream) and f1f_stream[j] != 0:
            j += 1
        if j - i >= 4:
            record_starts.append((i, j, f1f_stream[i:j]))
        i = j
    else:
        i += 1

print(f"  Found {len(record_starts)} non-zero blocks")
for start, end, data in record_starts[:10]:
    print(f"    [{start}-{end-1}] ({end-start} bytes): {data.hex()}")
    # Try to decode as 5-byte records
    if (end - start) % 5 == 0:
        print(f"      -> {(end-start)//5} records of 5 bytes")
        for k in range(0, end-start, 5):
            rec = data[k:k+5]
            print(f"        record {k//5}: {rec.hex()} = {list(rec)}")
    elif (end - start) % 6 == 0:
        print(f"      -> {(end-start)//6} records of 6 bytes")
        for k in range(0, end-start, 6):
            rec = data[k:k+6]
            print(f"        record {k//6}: {rec.hex()} = {list(rec)}")


# Now let's look at the 0x20 track packets (new session)
print("\n\nFeature 0x20 track data analysis (frames 5733 and 5737):")
f20_track_packets = [
    "05ffd3e5f9d75dffffd3e3f9d75dffffd3e1f9df5dffffd3dff9df5dffffd3ddf9e75dffffd3dbf9e75dffffd3d9f8c75dffffd3d7f9ee5dffffd3d5f8d25dffffd3d3f9ee5dffffd3d1f8d25dffffd3cff9ee57ffffd3cdf8c75dffffd3cbf9f557ffffd3c9f8d25dffffd3c7f9f557ffffd3c5f9f55dffffd2fff9ee57ffffd2fdf9ee5dffffd2fbf9f557ffffd2f9f9f55dffffd2f7f9f55dffffd2f5f9f55dffffd2f3f9ee5dffffd2f1f9ee5dffffd2eff9e75dffffd2edf9e757ffffd2ebf8c75dffffd2e9f9f557ffffd2e7f8d25dffffd2e5f9f557ffffd2e3f8dd5dffffd2e1f9f55dffffd2dff8d25dffffd2ddf9fc5dffffd2dbf8e75dffffd2d9f8e75dffffd2d7facd57ffffd2d5f8e75dffffd2d3f9fc57ffffd2d1f8dd5dffffd2cff9f557ffffd2cdf8dd5dffffd2cbf9f55dffffd2c9f8c75dffffd2c7f9f55dffffd2c5f9f55dffffd1fff9e75dffffd1fdf9e75dffffd1fbf9ee5dffffd1f9f9ee5dffffd1f7f9f55dffffd1f5f9f55dffffd1f3f8dd57ffffd1f1f9fc5dffffd1eff8d25dffffd1edf9ee5dffffd1ebf8d25dffffd1e9f9ee5dffffd1e7f8c75dffffd1e5f9e757ffffd1e3f7f85dffffd1e1f9",
    "05df57ffffd1dff9df5dffffd1ddf9df5dff",
]

f20_track_stream = b''
for pkt in f20_track_packets:
    raw = bytes.fromhex(pkt)
    stream_part = bytes(b ^ 0xff for b in raw[1:])
    f20_track_stream += stream_part

# The track data might start immediately (skip any header at beginning)
print(f"  Track stream length: {len(f20_track_stream)} bytes")
print(f"  First 30 raw bytes: {f20_track_stream[:30].hex()}")

# Find the actual data start - look for non-ff runs
# (since 0x00 raw -> 0xff XOR'd = padding; actual data has various values)
first_nonzero = -1
for i, b in enumerate(f20_track_stream):
    if b != 0xff:
        first_nonzero = i
        break

print(f"  First non-padding byte at: {first_nonzero}")

# After the padding, what do we have?
# Previous analysis showed 7-byte records starting from t=26s:
# [0x00][0x2c/0x2e?][seconds][0x06][pace_val][cadence_raw][0x00]

# Let's look for non-ff regions
i = 0
blocks = []
while i < len(f20_track_stream):
    if f20_track_stream[i] != 0xff:
        j = i
        while j < len(f20_track_stream) and f20_track_stream[j] != 0xff:
            j += 1
        blocks.append((i, j, f20_track_stream[i:j]))
        i = j
    else:
        i += 1

print(f"  Non-padding blocks: {len(blocks)}")
for bstart, bend, bdata in blocks:
    print(f"  Block [{bstart}-{bend-1}] ({bend-bstart} bytes): {bdata.hex()}")

# Now try to decode the 7-byte records
# The previous analysis found format:
# [0x00][0x2c][seconds][0x06][pace_val][cadence_raw][0x00]
# But with pace_val like 0x28=40 and cadence_raw 0xa2=162 -- those don't match directly

# Let me try full combined track including both packets
all_track = f20_track_stream
# Find the continuous non-ff block
nonff_start = None
nonff_end = None
for i, b in enumerate(all_track):
    if b != 0xff:
        if nonff_start is None:
            nonff_start = i
        nonff_end = i + 1

if nonff_start is not None:
    track_data = all_track[nonff_start:nonff_end]
    print(f"\n  Continuous track data: [{nonff_start}-{nonff_end-1}] ({len(track_data)} bytes)")
    print(f"  Hex: {track_data.hex()}")

    # Try 7-byte records
    num_7byte = len(track_data) // 7
    print(f"\n  Trying {num_7byte} records of 7 bytes:")
    for k in range(num_7byte):
        rec = track_data[k*7:(k+1)*7]
        # [0]=??, [1]=??, [2]=seconds, [3]=??, [4]=pace_raw, [5]=cadence_raw, [6]=??
        print(f"    record {k:2d}: {rec.hex()} | sec={rec[2]} pace_raw={rec[4]} cad_raw={rec[5]}")

    # Try 6-byte records
    num_6byte = len(track_data) // 6
    print(f"\n  Trying {num_6byte} records of 6 bytes:")
    for k in range(num_6byte):
        rec = track_data[k*6:(k+1)*6]
        print(f"    record {k:2d}: {rec.hex()} | bytes: {list(rec)}")

    # Try 5-byte records
    num_5byte = len(track_data) // 5
    print(f"\n  Trying {num_5byte} records of 5 bytes:")
    for k in range(num_5byte):
        rec = track_data[k*5:(k+1)*5]
        print(f"    record {k:2d}: {rec.hex()} | bytes: {list(rec)}")

# Now check the feature 0x20 summary header more carefully for distance
print("\n\n== Summary: Checking for distance=60 and max_pace=654 ==")
print("\nFeature 0x20 header (full, skip type byte, XOR):")
f20_header_full = "0501ecffbdbcff00000000ffffffffffff01b3ea73c2fffee9fffeedecfffcffffff95ff"
f20_h_raw = bytes.fromhex(f20_header_full)
f20_h_dec = bytes(b ^ 0xff for b in f20_h_raw[1:])  # skip type byte 0x05
print(f"  Decoded bytes ({len(f20_h_dec)} non-padding): {f20_h_dec[:40].hex()}")
for i, b in enumerate(f20_h_dec):
    if b != 0 and b != 0xff:
        print(f"  [{i}] = 0x{b:02x} = {b}")

print("\n  Search in f20 header:")
for i in range(len(f20_h_dec)-2):
    v8 = f20_h_dec[i]
    v16le = f20_h_dec[i] | (f20_h_dec[i+1] << 8)
    v16be = (f20_h_dec[i] << 8) | f20_h_dec[i+1]
    if v8 == 60: print(f"  dist8 at [{i}]={v8}")
    if v16le == 60: print(f"  dist16le at [{i}]={v16le}")
    if v16le == 654: print(f"  maxpace16le at [{i}]={v16le}")
    if v16be == 654: print(f"  maxpace16be at [{i}]={v16be}")
    if v8 == 0x0a and f20_h_dec[i+1] == 0x36: print(f"  maxpace_bcd 10:54 at [{i}]")

# Also check: distance might be in decameters (0.1km = 100m = raw 6?)
# or maybe in 10m units (60m = 6 in 10m units, or 600 in cm*100)
# Or maybe it's encoded as meters LE16: 60 = 0x003c
print("\n  Check for 60/6/600/6000:")
for i in range(len(f20_h_dec)-2):
    v8 = f20_h_dec[i]
    v16le = f20_h_dec[i] | (f20_h_dec[i+1] << 8)
    for target in [6, 60, 600, 6000]:
        if v8 == target: print(f"  [{i}] 8bit = {target}")
        if v16le == target: print(f"  [{i}] 16bit_le = {target}")
