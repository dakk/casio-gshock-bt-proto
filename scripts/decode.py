import sys

# Decode feature 0x1e CONVOY data from frame 5483
# Known values: duration=78s, distance=0.06km=60m, avg_pace=1140s/km, max_pace=654s/km, calories=3, cadence=106fpm

raw_1e = bytes.fromhex("0500ffff010000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f8ffecffeefeffffd8ffffffecfffffffefffffff7d9dffbd6ecdcb8d9dffbd6ecdafaff5fb8ffff3fb4ffb3ea73c2fffeedecfffcffffff95ff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000eb27")

print("Raw length:", len(raw_1e), "bytes")
print("Type byte: 0x%02x" % raw_1e[0])

# XOR all bytes (including type byte)
xor_all = bytes([b ^ 0xff for b in raw_1e])
print("\nXOR all bytes, first 2: 0x%02x 0x%02x = length=%d" % (xor_all[0], xor_all[1], xor_all[0] | (xor_all[1] << 8)))

# Find non-zero bytes in XOR'd data
print("\nNon-zero bytes in XOR(all):")
for i, b in enumerate(xor_all):
    if b \!= 0:
        print("  [%3d] 0x%02x (%3d)" % (i, b, b))

print("\nLooking for key values in xor_all:")
targets = [(78,'duration'), (60,'dist_m'), (600,'dist_dm'), (1140,'avg_pace'), (654,'max_pace'), (3,'calories'), (106,'cadence')]

for i in range(len(xor_all)-1):
    val16_le = xor_all[i] | (xor_all[i+1] << 8)
    for v, name in targets:
        if val16_le == v:
            print("  MATCH16_LE [%d:%d] = %s(%d)" % (i, i+1, name, v))
        if xor_all[i] == v:
            print("  MATCH8 [%d] = %s(%d)" % (i, name, v))

# Also search raw (no XOR)
print("\nLooking for key values in RAW (no XOR):")
for i in range(len(raw_1e)-1):
    val16_le = raw_1e[i] | (raw_1e[i+1] << 8)
    for v, name in targets:
        if val16_le == v:
            print("  MATCH16_LE [%d:%d] = %s(%d)" % (i, i+1, name, v))
        if raw_1e[i] == v:
            print("  MATCH8 [%d] = %s(%d)" % (i, name, v))
