#!/usr/bin/env python3
import subprocess

LOG = '/home/dakk/Repositories/Gadgetbridge/btsniff/btsnoop_hci_3.log'

def run_tshark(filt):
    r = subprocess.run(['tshark','-r',LOG,'-Y',filt,'-T','fields',
        '-e','frame.number','-e','frame.time_relative',
        '-e','btatt.handle','-e','btatt.opcode','-e','btatt.value'],
        capture_output=True, text=True)
    frames = []
    for line in r.stdout.strip().split('\n'):
        if not line.strip(): continue
        parts = line.strip().split('\t')
        try:
            fno=int(parts[0]); t=float(parts[1])
            handle=int(parts[2],16) if parts[2] else 0
            opcode=parts[3] if len(parts)>3 else ''
            val=bytes.fromhex(parts[4].replace(':','')) if len(parts)>4 and parts[4] else b''
            frames.append({'fno':fno,'t':t,'handle':handle,'opcode':opcode,'value':val})
        except:
            pass
    return frames

def hx(d, n=None):
    d = d[:n] if n else d
    return ' '.join(f'{b:02x}' for b in d)

frames = run_tshark('btatt.handle == 0x0011 || btatt.handle == 0x0014')

print('=== Q7: ACK FORMAT - DETAILED COMPARISON ===')
print()

acks = [f for f in frames if f['handle']==0x0011 and f['value']
        and f['value'][0]==0x04 and f['opcode'] in ('0x12','0x52')]
print('ACK frames on h0011:')
for f in acks:
    feat = f['value'][1] if len(f['value'])>1 else 0
    java_ack = bytes([0x04, feat, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    match_str = 'MATCH' if f['value'] == java_ack else 'MISMATCH'
    print(f'  frame {f["fno"]:5d}  feat=0x{feat:02x}  {hx(f["value"])}  java={hx(java_ack)}  {match_str}')
    if f['value'] != java_ack:
        print(f'    len cap={len(f["value"])} java={len(java_ack)}')
        for i in range(max(len(f['value']), len(java_ack))):
            a = f['value'][i] if i < len(f['value']) else -1
            b = java_ack[i] if i < len(java_ack) else -1
            if a != b:
                print(f'    byte[{i}]: cap=0x{a:02x}, java=0x{b:02x}')

print()
print('=== ALL PHONE WRITES ON h0014 (the missing sub-protocol) ===')
h0014_pw = [f for f in frames if f['handle']==0x0014 and f['opcode']=='0x52']
print(f'Phone WriteNoResp on h0014: {len(h0014_pw)} total')
for f in h0014_pw:
    print(f'  frame {f["fno"]:5d} @{f["t"]:.3f}s  {hx(f["value"])}')

print()
print('=== 0x07 CANCEL/ABORT MESSAGES ON h0011 ===')
h0011_07 = [f for f in frames if f['handle']==0x0011 and f['value'] and f['value'][0]==0x07]
print(f'Frames on h0011 starting with 0x07: {len(h0011_07)}')
for f in h0011_07:
    feat = f['value'][1] if len(f['value'])>1 else 0
    print(f'  frame {f["fno"]:5d} @{f["t"]:.3f}s  feat=0x{feat:02x}  {hx(f["value"])}')

print()
print('=== 0x09 MESSAGES ON h0011 ===')
h0011_09 = [f for f in frames if f['handle']==0x0011 and f['value'] and f['value'][0]==0x09]
print(f'Frames on h0011 starting with 0x09: {len(h0011_09)}')
for f in h0011_09:
    feat = f['value'][1] if len(f['value'])>1 else 0
    print(f'  frame {f["fno"]:5d} @{f["t"]:.3f}s  feat=0x{feat:02x}  {hx(f["value"])}')

print()
print('=== ALL h0011 WRITES (phone->watch): complete list ===')
h0011_pw = [f for f in frames if f['handle']==0x0011 and f['opcode'] in ('0x12','0x52')]
for f in h0011_pw:
    cmd = f['value'][0] if f['value'] else 0xff
    feat = f['value'][1] if len(f['value'])>1 else 0
    cmd_names = {0x00: 'REQ', 0x04: 'ACK', 0x07: 'CANCEL', 0x09: 'STATUS?'}
    cmd_str = cmd_names.get(cmd, f'0x{cmd:02x}')
    offset = (f['value'][3]|(f['value'][4]<<8)) if len(f['value'])>=5 else 0
    param = f['value'][7] if len(f['value'])>=8 else 0
    offset_str = f' off=0x{offset:04x} param=0x{param:02x}' if cmd==0x00 else ''
    print(f'  frame {f["fno"]:5d} @{f["t"]:.3f}s  {cmd_str} feat=0x{feat:02x}{offset_str}  {hx(f["value"])}')
