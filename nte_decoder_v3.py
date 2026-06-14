#!/usr/bin/env python3
"""
NTE (Neverness to Everness / 異環) PCAP Decoder  v3.0
=====================================================
完整解析 NTE 私有協定：TCP 重組 → LE4 Frame 分割 → FlatBuffers 解析 → Quest Record 解析

已確認協定格式：
────────────────────────────────────────────────────────────────────
  [LE4 length]  Frame 0 (200B)   FlatBuffers init: server IP / build / session token
  [LE4 length]  Frame 1 (~392B)  FlatBuffers player: character / coords / relay / UID
  [LE4 length]  Frame 2 (72B)    FlatBuffers heartbeat
  [NO prefix]   Frame 3 (100KB+) World state:
                 ├─ Dense zone  [0:40960]   Binary game state (sub-frames)
                 └─ Sparse zone [40960:]    FlatBuffers quest/item string table

  Sparse zone record format (每筆 quest/redpoint/item record)：
    [1B  pad ]  [4B type_A]  [4B type_B]  [4B unknown_C]  [1B pad]
    [4B  str_bytelen (UTF-16 bytes + 2-byte null)]
    [UTF-16 LE string + 00 00]
    [4B progress1]  [4B progress2]  [4B progress3]  [4B progress4]  [4B progress5]

用法：
  python3 nte_decoder_v3.py <pcap_file> [target_ip]
  python3 nte_decoder_v3.py NTE2.pcap 34.110.242.50
  python3 nte_decoder_v3.py NTE2.pcap            # uses default IP
"""

import sys, struct, json, math, re, os
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("[!] pip install scapy"); sys.exit(1)

# ── output path ─────────────────────────────────────────────────────
OUTPUT_DIR = r"C:\Users\User\Desktop\py\pcap"

USE_COLOR = sys.stdout.isatty()
def _c(t, code): return f"\033[{code}m{t}\033[0m" if USE_COLOR else t
def green(t):  return _c(t, "32")
def yellow(t): return _c(t, "33")
def cyan(t):   return _c(t, "36")
def red(t):    return _c(t, "31")
def bold(t):   return _c(t, "1")
def dim(t):    return _c(t, "2")


# ════════════════════════════════════════════════════════════════════
#  TCP Stream Reassembly
# ════════════════════════════════════════════════════════════════════

def reassemble(pcap_path: str, target_ip: str) -> dict:
    pkts = rdpcap(pcap_path)
    print(f"[*] 讀取封包：{len(pkts)} 個")
    streams = defaultdict(list)
    for pkt in pkts:
        if not (IP in pkt and TCP in pkt): continue
        s, d = pkt[IP].src, pkt[IP].dst
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
        payload = bytes(pkt[TCP].payload)
        if payload and (s == target_ip or d == target_ip):
            streams[(s, sp, d, dp)].append((pkt[TCP].seq, payload))
    out = {}
    for key, segs in streams.items():
        segs.sort(key=lambda x: x[0])
        buf, last = bytearray(), None
        for seq, data in segs:
            if last is None or seq > last:
                buf.extend(data); last = seq + len(data)
        out[key] = bytes(buf)
    return out


# ════════════════════════════════════════════════════════════════════
#  FlatBuffers Blind Decoder  (Frame 0/1/2)
# ════════════════════════════════════════════════════════════════════

def _strings_utf8(data: bytes, min_len=4) -> list:
    out, cur = [], b""
    for b in data:
        if 32 <= b < 127: cur += bytes([b])
        else:
            if len(cur) >= min_len: out.append(cur.decode())
            cur = b""
    if len(cur) >= min_len: out.append(cur.decode())
    return out

def decode_flatbuffers(data: bytes) -> dict:
    r = {"format": "unknown", "fields": [], "strings": []}
    if len(data) < 8: return r
    root_off = struct.unpack_from("<I", data, 0)[0]
    if not (4 <= root_off < len(data)):
        r["strings"] = _strings_utf8(data)
        return r
    tp = root_off
    soff = struct.unpack_from("<i", data, tp)[0]
    vp = tp - soff
    if not (0 <= vp < len(data) and vp + 4 <= len(data)): return r
    vs, os_ = struct.unpack_from("<HH", data, vp)
    if not (4 <= vs <= 1024): return r
    r.update(format="flatbuffers", root_offset=root_off,
             vtable_size=vs, object_size=os_)
    nf = (vs - 4) // 2
    fields = []
    for fi in range(nf):
        fop = vp + 4 + fi*2
        if fop + 2 > len(data): break
        fo = struct.unpack_from("<H", data, fop)[0]
        if fo == 0:
            fields.append({"index": fi, "present": False}); continue
        ap = tp + fo
        fe = {"index": fi, "present": True, "offset": fo, "abs_pos": ap}
        if ap + 4 <= len(data):
            raw4 = data[ap:ap+4]
            fe.update(raw_hex=raw4.hex(),
                      as_int32=struct.unpack_from("<i", raw4)[0],
                      as_uint32=struct.unpack_from("<I", raw4)[0],
                      as_float32=round(struct.unpack_from("<f", raw4)[0], 6))
            # try as string offset
            if ap + 8 <= len(data):
                ind = struct.unpack_from("<I", raw4)[0]
                tgt = ap + ind
                if 0 < ind < len(data) and tgt + 4 <= len(data):
                    sl = struct.unpack_from("<I", data, tgt)[0]
                    if 0 < sl < 4096 and tgt + 4 + sl <= len(data):
                        try:
                            s = data[tgt+4:tgt+4+sl].decode("utf-8")
                            if sum(c.isprintable() for c in s)/max(len(s),1) > 0.8:
                                fe["string_value"] = s
                        except: pass
        fields.append(fe)
    r["fields"] = fields
    r["strings"] = _strings_utf8(data)
    return r


# ════════════════════════════════════════════════════════════════════
#  Quest Record Parser  (Sparse zone of Frame 3)
# ════════════════════════════════════════════════════════════════════

# Confirmed record layout (17-byte prefix):
#   [1B pad] [4B type_A] [4B type_B] [4B unknown_C] [1B pad] [4B str_bytelen]
#   [UTF-16 LE string incl. 2-byte null]
#   [4B p1] [4B p2] [4B p3] [4B p4] [4B p5]
# → total: 17 + str_bytelen + 20 bytes per record

RECORD_PREFIX = 17   # bytes before string start (ends with 4B str_bytelen)
# After string (incl 2-byte null), there are 7 bytes of suffix data before next record.
# At group boundaries the suffix is longer (23 bytes).
# Most robust parse: scan forward for next [4B str_bytelen][ASCII UTF-16] pattern.

def _is_ascii_utf16_check(data: bytes, sbl: int) -> bool:
    """Verify str_bytelen matches actual ASCII UTF-16 content."""
    if sbl < 10 or sbl > 512 or sbl % 2 != 0: return False
    str_data = data[:sbl-2]
    if len(str_data) < sbl-2: return False
    for i in range(0, len(str_data), 2):
        if i+1 >= len(str_data): return False
        if str_data[i+1] != 0: return False
        if not (32 <= str_data[i] <= 126): return False
    return True

def parse_quest_records(sparse: bytes, start_offset: int) -> list:
    """
    Parse quest/item/redpoint records from the sparse zone.
    Uses scan-forward approach: after each record, scan for the next
    [str_bytelen][ASCII UTF-16] pattern rather than assuming fixed suffix length.
    """
    records = []
    pos = start_offset  # points to first record's 17-byte prefix start

    while pos + RECORD_PREFIX + 4 <= len(sparse):
        # The last 4 bytes of the 17-byte prefix ARE the str_bytelen
        sbl_pos = pos + RECORD_PREFIX - 4
        str_bytelen = struct.unpack_from("<I", sparse, sbl_pos)[0]

        if str_bytelen == 0 or str_bytelen > 512 or str_bytelen % 2 != 0:
            break

        str_start = pos + RECORD_PREFIX
        str_end   = str_start + str_bytelen  # includes 2-byte null

        if str_end > len(sparse): break

        # Verify it really is ASCII UTF-16
        if not _is_ascii_utf16_check(sparse[str_start:], str_bytelen):
            break

        # Decode (exclude null)
        raw_str = sparse[str_start : str_end - 2]
        try:
            quest_name = raw_str.decode("utf-16-le")
        except UnicodeDecodeError:
            break

        if not re.search(r'[a-zA-Z]{2}', quest_name):
            break

        # Extract progress values from the 7-byte suffix
        # Layout: [4B val_a][2B val_b][1B unused/boundary]
        suf = sparse[str_end : str_end + 7]
        val_a = struct.unpack_from("<I", suf, 0)[0] if len(suf) >= 4 else 0
        val_b = struct.unpack_from("<H", suf, 4)[0] if len(suf) >= 6 else 0

        # Read type fields from prefix
        type_a = struct.unpack_from("<I", sparse, pos + 1)[0] if pos+5 <= len(sparse) else 0
        type_b = struct.unpack_from("<I", sparse, pos + 5)[0] if pos+9 <= len(sparse) else 0

        records.append({
            "name":     quest_name,
            "type_a":   type_a,
            "type_b":   type_b,
            "val_a":    val_a,
            "val_b":    val_b,
            "offset":   pos,
        })

        # Scan forward for next record prefix (find next [4B sbl][ASCII UTF-16])
        search_start = str_end
        found_next = False
        for skip in range(0, 8192):
            candidate = search_start + skip
            if candidate + RECORD_PREFIX + 4 > len(sparse): break
            next_sbl = struct.unpack_from("<I", sparse, candidate + RECORD_PREFIX - 4)[0]
            if _is_ascii_utf16_check(sparse[candidate + RECORD_PREFIX:], next_sbl):
                # Check it decodes to a reasonable quest name
                try:
                    ns = sparse[candidate+RECORD_PREFIX : candidate+RECORD_PREFIX+next_sbl-2].decode("utf-16-le")
                    if len(ns) >= 4 and re.search(r'[A-Za-z]{3}', ns):
                        pos = candidate
                        found_next = True
                        break
                except: pass
        if not found_next:
            break

    return records


def find_record_start(sparse: bytes) -> int:
    """
    Scan sparse zone for the first valid quest record.
    Strategy: find position where [4B str_bytelen] is followed by pure ASCII UTF-16 LE
    text (each char is [XX 00] where XX is 32-126).  Record prefix is RECORD_PREFIX-4
    bytes before that str_bytelen field.
    """
    def _is_ascii_utf16(data: bytes, min_chars: int = 8) -> bool:
        if len(data) < min_chars * 2 or len(data) % 2 != 0:
            return False
        for i in range(0, len(data), 2):
            if i+1 >= len(data): return False
            if data[i+1] != 0: return False
            if not (32 <= data[i] <= 126): return False
        return True

    for pos in range(0, min(len(sparse) - 4, 65536)):
        sbl = struct.unpack_from("<I", sparse, pos)[0]
        if not (10 <= sbl <= 512 and sbl % 2 == 0):
            continue
        str_data = sparse[pos+4 : pos+4+sbl-2]
        if _is_ascii_utf16(str_data, min_chars=8):
            s = str_data.decode("utf-16-le")
            # Must look like a CamelCase identifier (quest/item name)
            if re.search(r'[A-Z][a-z]{3}', s):
                rec_start = pos - (RECORD_PREFIX - 4)  # 13 bytes before str_bytelen
                return max(0, rec_start)
    return -1


def categorize(name: str) -> str:
    n = name.lower()
    if any(x in n for x in ["fish", "handbook"]):        return "fishing"
    if "redpoint" in n:                                   return "ui_redpoint"
    if any(x in n for x in ["propbox", "httarget"]):     return "world_object"
    if any(x in n for x in ["item_"]):                   return "item"
    if any(x in n for x in ["ad", "achieve"]):           return "achievement"
    if any(x in n for x in ["combat", "actcity", "opact",
                             "newbie", "rb_cyclic",
                             "awakfrom", "mysteries",
                             "diyboss", "quest_bagel",
                             "seasonquest", "weeklyquest"]): return "quest"
    return "other"


# ════════════════════════════════════════════════════════════════════
#  Main
# ════════════════════════════════════════════════════════════════════

def hexdump(data: bytes, limit=256) -> str:
    lines = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i+16]
        hx  = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {i:04x}  {hx:<47}  {asc}")
    return "\n".join(lines)

def entropy(data: bytes) -> float:
    if not data: return 0.0
    cnt, n = Counter(data), len(data)
    return -sum((c/n)*math.log2(c/n) for c in cnt.values() if c > 0)


def main():
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "NTE2.pcap"
    target_ip = sys.argv[2] if len(sys.argv) > 2 else "34.110.242.50"

    print(bold("=" * 72))
    print(bold("  NTE PCAP Decoder  v3.0"))
    print(f"  檔案：{pcap_path}  |  目標：{target_ip}")
    print(bold("=" * 72))

    streams = reassemble(pcap_path, target_ip)
    if not streams:
        print(red(f"[!] 未找到 {target_ip} 的流量")); return

    print(f"[*] 找到 {len(streams)} 個含 payload 的方向流\n")

    all_output = {}

    for key, raw in sorted(streams.items(), key=lambda x: -len(x[1])):
        src, sport, dst, dport = key
        ent = entropy(raw[:min(len(raw), 4096)])
        print(bold("─" * 72))
        print(f"  {cyan('流向')}：{src}:{sport} → {dst}:{dport}  ({len(raw)} bytes  entropy={ent:.2f})")
        print(hexdump(raw))

        # ── LE4 frame splitting ──────────────────────────────────
        # Protocol: after the small init frames (Frame 0/1/2), the big world-state
        # frame has NO LE4 prefix — it starts directly where LE4 framing breaks.
        frames = []
        pos = 0
        while pos + 4 <= len(raw):
            l = struct.unpack_from("<I", raw, pos)[0]
            if l == 0 or l > 10_000_000:
                # Remaining bytes = world-state frame (no length prefix)
                leftover = raw[pos:]
                if len(leftover) >= 512:
                    frames.append({"declared": len(leftover), "data": leftover,
                                   "truncated": False, "missing": 0, "no_prefix": True})
                break
            end = pos + 4 + l
            trunc = end > len(raw)
            frames.append({"declared": l, "data": raw[pos+4 : min(end, len(raw))], "truncated": trunc,
                           "missing": max(0, end - len(raw)), "no_prefix": False})
            if trunc: break
            pos = end

        print(f"\n  [LE4 Frames] {len(frames)} 個" + (yellow("（最後一個截斷）") if frames and frames[-1]["truncated"] else ""))

        init_frames_result = []
        world_state_result = None

        for i, fm in enumerate(frames):
            fd = fm["data"]
            fe = entropy(fd[:min(len(fd), 4096)])
            is_world = fm.get("no_prefix", False) and len(fd) > 10000
            tag = yellow(" [TRUNC]") if fm["truncated"] else ""
            fmt_tag = cyan("WorldState") if is_world else "FlatBuffers"

            print(f"\n  ── {bold(f'Frame #{i+1}')} ({fm['declared']} declared / {len(fd)} available){tag}  [{fmt_tag}] entropy={fe:.2f}")

            if not is_world:
                # ── FlatBuffers decode ───────────────────────────
                fb = decode_flatbuffers(fd)
                print(f"  格式：{green(fb['format'])}", end="")
                if fb['format'] == 'flatbuffers':
                    print(f"  vtable_size={fb['vtable_size']}  obj_size={fb['object_size']}")
                    for f in fb["fields"]:
                        if not f.get("present"): continue
                        line = f"    field[{f['index']}]  {f.get('raw_hex','')}"
                        if "string_value" in f:
                            line += green(f"  → \"{f['string_value']}\"")
                        else:
                            line += f"  u32={f['as_uint32']}  f32={f['as_float32']}"
                        print(line)
                else:
                    print()
                strs = fb.get("strings", [])
                if strs:
                    print(f"  字串: {cyan(str(strs[:8]))}")
                init_frames_result.append({"frame": i, **fb})

            else:
                # ── World State decode ───────────────────────────
                print(f"  大小分區：dense=[0:{min(40960,len(fd))}]  sparse=[{min(40960,len(fd))}:{len(fd)}]")

                dense  = fd[:40960]  if len(fd) >= 40960 else fd
                sparse = fd[40960:]  if len(fd) >= 40960 else b""

                # ── Sparse zone: parse FlatBuffers header ────────
                if len(sparse) >= 16:
                    root_off = struct.unpack_from("<I", sparse, 0)[0]
                    print(f"\n  [Sparse FlatBuffers header]  root_offset={root_off}")
                    if root_off < len(sparse):
                        tp = root_off
                        soff = struct.unpack_from("<i", sparse, tp)[0]
                        vp = tp - soff
                        if 0 <= vp + 4 <= len(sparse):
                            vs, os_ = struct.unpack_from("<HH", sparse, vp)
                            nf2 = (vs - 4) // 2
                            print(f"  vtable_size={vs}  obj_size={os_}  fields={nf2}")
                            for fi in range(nf2):
                                fop2 = vp + 4 + fi*2
                                fo2 = struct.unpack_from("<H", sparse, fop2)[0] if fop2+2<=len(sparse) else 0
                                ap2 = tp + fo2
                                u32 = struct.unpack_from("<I", sparse, ap2)[0] if fo2 and ap2+4<=len(sparse) else 0
                                print(f"    field[{fi}] u32={u32}")

                # ── Quest record parsing ─────────────────────────
                if len(sparse) > 6000:
                    start_off = find_record_start(sparse)
                    if start_off < 0:
                        print(yellow("  [!] 找不到 quest record 起始位置"))
                    else:
                        records = parse_quest_records(sparse, start_off)
                        print(f"\n  [{green('Quest/Item Records')}]  起始 offset={start_off}  解析到 {len(records)} 筆")

                        # Categorize
                        by_cat = defaultdict(list)
                        for r in records:
                            by_cat[categorize(r["name"])].append(r)

                        for cat, items in sorted(by_cat.items(), key=lambda x: -len(x[1])):
                            print(f"\n  ── {bold(cat)} ({len(items)} 筆) ──")
                            for r in items[:20]:
                                prog_str = f"val_a={r["val_a"]} val_b={r["val_b"]}"
                                print(f"    {cyan(r['name']):<45}  type_a={r['type_a']}  type_b={r['type_b']}  {dim(prog_str)}")
                            if len(items) > 20:
                                print(dim(f"    ... +{len(items)-20} more"))

                        world_state_result = {
                            "record_start_offset": start_off,
                            "total_records": len(records),
                            "categories": {cat: [r["name"] for r in items]
                                          for cat, items in by_cat.items()},
                            "records_full": records,
                        }

        stream_key = f"{src}:{sport}->{dst}:{dport}"
        all_output[stream_key] = {
            "total_bytes": len(raw),
            "entropy": round(ent, 3),
            "init_frames": init_frames_result,
            "world_state": world_state_result,
        }
        print()

    # ── Save JSON ──────────────────────────────────────────────────
    def _clean(obj):
        if isinstance(obj, dict):  return {k: _clean(v) for k, v in obj.items()}
        if isinstance(obj, list):  return [_clean(v) for v in obj]
        if isinstance(obj, bytes): return obj.hex()
        return obj

    out_json = os.path.join(OUTPUT_DIR, "nte_decoded_v3.json")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(_clean(all_output), f, ensure_ascii=False, indent=2, default=str)
    print(f"[*] JSON 儲存至：{bold(out_json)}")

    # ── Save CSV (quest list) ──────────────────────────────────────
    out_csv = os.path.join(OUTPUT_DIR, "nte_quests_v3.csv")
    with open(out_csv, "w", encoding="utf-8-sig") as f:
        f.write("quest_name,category,type_a,type_b,val_a,val_b\n")
        for stream_data in all_output.values():
            ws = stream_data.get("world_state")
            if not ws: continue
            for r in ws.get("records_full", []):
                prog = [r.get("val_a",0), r.get("val_b",0)]
                f.write(f"{r['name']},{categorize(r['name'])},{r['type_a']},{r['type_b']},{prog[0]},{prog[1]}\n")
    print(f"[*] CSV  儲存至：{bold(out_csv)}")

    # ── Save player info TXT ───────────────────────────────────────
    out_txt = os.path.join(OUTPUT_DIR, "nte_player_info.txt")
    with open(out_txt, "w", encoding="utf-8") as f:
        for stream_data in all_output.values():
            for fr in stream_data.get("init_frames", []):
                strs = fr.get("strings", [])
                if strs:
                    f.write(f"Frame {fr['frame']} strings:\n")
                    for s in strs:
                        f.write(f"  {s}\n")
                    f.write("\n")
    print(f"[*] TXT  儲存至：{bold(out_txt)}")

if __name__ == "__main__":
    main()
