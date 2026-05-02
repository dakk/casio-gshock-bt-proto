#!/usr/bin/env python3
"""Analyze block collection sessions with duplicate request handling"""
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

def frames(h):
    out = subprocess.run(['tshark','-r',LOG,'-Y',f'btatt.handle == {h}','-T','fields','-e','frame.number','-e','btatt.value'],
        capture_output=True, text=True).stdout.strip()
    res = []
    for line in out.split('\n'):
        p = line.strip().split('\t')
        try: res.append((int(p[0]), bytes.fromhex(p[1].replace(':',''))))
        except: pass
    return res

def xd(d):
    b = bytearray(d)
    for i in range(1,len(b)): b[i] ^= 0xFF
    return bytes(b)

f11 = frames('0x0011'); f14 = frames('0x0014')
all_f = sorted([(n,'11',d) for n,d in f11]+[(n,'14',d) for n,d in f14])

sessions = []
sess_data = bytearray()
sess_off = None

for n, h, d in all_f:
    if h == '11' and len(d) >= 5 and d[0] == 0x00 and d[1] == 0x1f:
        off = d[3] | (d[4] << 8)
        if sess_off is None:
            sess_off = off
            sess_data = bytearray()
            print(f"  Starting session 0x{off:04x} at frame {n}")
        elif off == sess_off:
            print(f"  DUPLICATE req 0x{off:04x} at frame {n}, collected so far={len(sess_data)}")
        else:
            print(f"  Ending session 0x{sess_off:04x}: {len(sess_data)} bytes")
            sessions.append((sess_off, bytes(sess_data)))
            sess_off = off
            sess_data = bytearray()
            print(f"  Starting session 0x{off:04x} at frame {n}")
    elif h == '14' and d[0] == 0x05 and sess_off is not None:
        dec = xd(d)
        sess_data.extend(dec[3:])

if sess_off is not None:
    print(f"  Ending session 0x{sess_off:04x}: {len(sess_data)} bytes")
    sessions.append((sess_off, bytes(sess_data)))

print(f"\nSessions: {len(sessions)}")
for off, data in sessions:
    HEADER = 15
    hdr = data[:HEADER]
    next_ptr = hdr[5] | (hdr[6] << 8) if len(hdr) >= 7 else 0xdead
    print(f"\nBlock 0x{off:04x}: {len(data)} bytes")
    print(f"  Header: {' '.join(f'{b:02x}' for b in hdr)}")
    print(f"  next_ptr=0x{next_ptr:04x}")
    payload = data[HEADER:]
    ff_trail = 0
    for b in reversed(payload):
        if b == 0xff: ff_trail += 1
        else: break
    useful = payload[:len(payload) - ff_trail]
    useful7 = useful[:len(useful) // 7 * 7]
    print(f"  payload={len(payload)}B, ff_trail={ff_trail}, useful_recs={len(useful7)//7}")

    print(f"  First 5 records:")
    for i in range(min(5, len(useful7)//7)):
        r = useful7[i*7:(i+1)*7]
        print(f"    rec[{i}] {' '.join(f'{b:02x}' for b in r)}")
    print(f"  Last 5 records:")
    n_recs = len(useful7) // 7
    for i in range(max(0, n_recs-5), n_recs):
        r = useful7[i*7:(i+1)*7]
        print(f"    rec[{i}] {' '.join(f'{b:02x}' for b in r)}")

# Now do the CORRECT block collection:
# Each 0x47a0 offset = activity1 block1 (4080 bytes)
# 0x47a0 chains to 0x4be0 = activity1 block2
# 0x4bf0 = activity2 block1
# The duplicate requests mean we collected each block TWICE
# So 8160 bytes = 2 * 4080 for block2 and block3

print("\n=== Correct: each session uses only first 4080 bytes ===")
for off, data in sessions:
    data = data[:4080]
    HEADER = 15
    payload = data[HEADER:]
    ff_trail = 0
    for b in reversed(payload):
        if b == 0xff: ff_trail += 1
        else: break
    useful = payload[:len(payload) - ff_trail]
    useful7 = useful[:len(useful) // 7 * 7]
    n_recs = len(useful7) // 7
    print(f"\nBlock 0x{off:04x} (first 4080B): {n_recs} useful records")
    print(f"  Last 3 records:")
    for i in range(max(0, n_recs-3), n_recs):
        r = useful7[i*7:(i+1)*7]
        t = r[0]*60 + r[1]
        p = r[2]*60 + r[3]
        print(f"    rec[{i}] {' '.join(f'{b:02x}' for b in r)} t={t}s pace={p}s/km")
