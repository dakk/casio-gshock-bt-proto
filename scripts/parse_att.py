#!/usr/bin/env python3
# btsnoop (H4) -> ATT text dump, CID 4 only, with L2CAP reassembly.
# usage: parse_att.py <btsnoop.log>
import struct, sys, datetime

OPS = {0x01:"ERROR_RSP",0x02:"MTU_REQ",0x03:"MTU_RSP",0x04:"FIND_INFO_REQ",
0x05:"FIND_INFO_RSP",0x06:"FIND_BY_TYPE_REQ",0x07:"FIND_BY_TYPE_RSP",
0x08:"READ_BY_TYPE_REQ",0x09:"READ_BY_TYPE_RSP",0x0a:"READ_REQ",0x0b:"READ_RSP",
0x0c:"READ_BLOB_REQ",0x0d:"READ_BLOB_RSP",0x10:"READ_BY_GROUP_REQ",
0x11:"READ_BY_GROUP_RSP",0x12:"WRITE_REQ",0x13:"WRITE_RSP",
0x16:"PREPARE_WRITE_REQ",0x17:"PREPARE_WRITE_RSP",0x18:"EXECUTE_WRITE_REQ",
0x19:"EXECUTE_WRITE_RSP",0x1b:"NTF",0x1d:"IND",0x1e:"CNF",0x52:"WRITE_CMD"}
EPOCH_DELTA_US = 0x00dcddb30f2f8000  # btsnoop epoch (0 AD) -> unix

def hx(b): return " ".join(f"{x:02x}" for x in b)

def main(path):
    data = open(path,"rb").read()
    assert data[:8] == b"btsnoop\x00"
    off = 16
    # L2CAP reassembly state per (direction): (cid, sdu_bytes, remaining)
    pend = {}
    while off + 24 <= len(data):
        olen, ilen, flags, drops, ts = struct.unpack(">IIIIQ", data[off:off+24])
        off += 24
        pkt = data[off:off+ilen]; off += olen if olen >= ilen else ilen
        if len(pkt) < 5 or pkt[0] != 0x02:  # not H4 ACL
            continue
        sent = (flags & 1) == 0  # 0 = host->controller = phone->watch
        direc = "->" if sent else "<-"
        h0, h1, dlen = pkt[1], pkt[2], pkt[3] | (pkt[4]<<8)
        pb = ((h0 | (h1<<8)) >> 12) & 3
        frag = pkt[5:5+dlen]
        key = sent
        sdu = None
        if pb in (0, 2):  # first fragment: L2CAP header
            if len(frag) < 4: continue
            l2len, cid = frag[0] | (frag[1]<<8), frag[2] | (frag[3]<<8)
            body = frag[4:]
            if cid != 4:
                pend.pop(key, None); continue
            if len(body) >= l2len:
                sdu = body[:l2len]
            else:
                pend[key] = [l2len, bytearray(body)]
        elif pb == 1:  # continuation
            st = pend.get(key)
            if not st: continue
            st[1] += frag
            if len(st[1]) >= st[0]:
                sdu = bytes(st[1][:st[0]]); pend.pop(key, None)
        if not sdu: continue
        op = sdu[0]
        name = OPS.get(op, f"OP{op:02x}")
        t = datetime.datetime.fromtimestamp((ts - EPOCH_DELTA_US)/1e6)
        stamp = t.strftime("%m-%d %H:%M:%S.") + f"{t.microsecond//1000:03d}"
        rest = sdu[1:]
        if op in (0x1b, 0x1d, 0x12, 0x52, 0x0a, 0x0c, 0x16) and len(rest) >= 2:
            h = rest[0] | (rest[1]<<8)
            print(f"{stamp} {direc} {name} h{h:04x} {hx(rest[2:])}")
        else:
            print(f"{stamp} {direc} {name} {hx(rest)}")

main(sys.argv[1])
