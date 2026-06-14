#!/usr/bin/env python3
"""
NTE Dense Zone Differ  v1.0
============================
比對多份 PCAP 的 Frame 4 Dense Zone，定位 HP/能量/技能CD 等即時數值欄位。

使用流程：
  1. 錄製「滿血」PCAP：  python dense_zone_differ.py --add full_hp.pcap   --tag full_hp
  2. 錄製「殘血」PCAP：  python dense_zone_differ.py --add low_hp.pcap    --tag low_hp
  3. 執行比對：          python dense_zone_differ.py --diff full_hp low_hp
  4. 查看所有快照：      python dense_zone_differ.py --list
  5. 匯出 CSV：          python dense_zone_differ.py --diff full_hp low_hp --csv out.csv

Dense Zone 位置：Frame 4 (no LE4 prefix) 的前 40960 bytes
已知結構（來自先前逆向）：
  [0:2165]   Header / metadata
  [2165:]    Sub-frames（兩個 LE4，各含遊戲狀態數值）

因為兩份 PCAP 的 Dense Zone 開頭含有 per-session counter/timestamp（37410/40960 bytes 都不同），
本工具採用「錨點對齊 + 定向 diff」而非直接 byte-by-byte，避免假陽性。

已知錨點：
  - 玩家 UID uint64 LE (218210397178) 出現在 Frame 2（不在 Dense Zone）
  - Dense Zone 內的 UTF-16 字串（CustomIcon, FilterState 等）可作為錨點
  - 0x88 0x01 這個 2-byte pattern 在 header 附近固定出現

輸出路徑：C:\\Users\\User\\Desktop\\py\\pcap\\
"""

import sys
import os
import struct
import json
import csv
import math
import re
import argparse
from collections import defaultdict, Counter
from pathlib import Path

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("[!] pip install scapy")
    sys.exit(1)

OUTPUT_DIR = r"C:\Users\User\Desktop\py\pcap"
SNAPSHOT_DB = os.path.join(OUTPUT_DIR, "dense_snapshots.json")
DENSE_SIZE   = 40960
TARGET_IP    = "34.110.242.50"

USE_COLOR = sys.stdout.isatty()
def _c(t, code): return f"\033[{code}m{t}\033[0m" if USE_COLOR else t
def green(t):  return _c(t, "32")
def yellow(t): return _c(t, "33")
def cyan(t):   return _c(t, "36")
def red(t):    return _c(t, "31")
def bold(t):   return _c(t, "1")
def dim(t):    return _c(t, "2")


# ════════════════════════════════════════════════════════════════════
#  PCAP 解析 / Dense Zone 提取
# ════════════════════════════════════════════════════════════════════

def reassemble(pcap_path: str, target_ip: str = TARGET_IP) -> dict:
    pkts = rdpcap(pcap_path)
    sp = defaultdict(list)
    for pkt in pkts:
        if not (IP in pkt and TCP in pkt): continue
        s, d = pkt[IP].src, pkt[IP].dst
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        pay = bytes(pkt[TCP].payload)
        if pay and (s == target_ip or d == target_ip):
            sp[(s, sport, d, dport)].append((pkt[TCP].seq, pay))
    out = {}
    for k, segs in sp.items():
        segs.sort(key=lambda x: x[0])
        buf, last = bytearray(), None
        for seq, data in segs:
            if last is None or seq > last:
                buf.extend(data); last = seq + len(data)
        out[k] = bytes(buf)
    return out


def extract_dense_zone(streams: dict) -> tuple[bytes | None, dict]:
    """回傳 (dense_bytes, meta)"""
    for key, raw in sorted(streams.items(), key=lambda x: -len(x[1])):
        src, sport, dst, dport = key
        if src != TARGET_IP or len(raw) < 1000: continue

        # Walk LE4 frames; world frame starts where framing breaks
        pos = 0
        init_frames = []
        while pos + 4 <= len(raw):
            l = struct.unpack_from("<I", raw, pos)[0]
            if l == 0 or l > 10_000_000:
                world = raw[pos:]
                dense = world[:DENSE_SIZE] if len(world) >= DENSE_SIZE else world
                # Extract player info from Frame 2
                player = _extract_player_info(init_frames)
                meta = {
                    "stream":      f"{src}:{sport}->{dst}:{dport}",
                    "total_bytes": len(raw),
                    "world_bytes": len(world),
                    "dense_bytes": len(dense),
                    "player":      player,
                }
                return dense, meta
            end = pos + 4 + l
            if pos + 4 <= len(raw) and end <= len(raw):
                init_frames.append(raw[pos+4:end])
            if end > len(raw): break
            pos = end
    return None, {}


def _extract_player_info(frames: list[bytes]) -> dict:
    """從 Frame 2 的 nested FlatBuffers 提取玩家資訊"""
    info = {}
    if len(frames) < 2: return info
    f1 = frames[1]
    if len(f1) < 140: return info
    try:
        # Nested table at tp=72 (confirmed from previous analysis)
        tp = 72
        soff = struct.unpack_from("<i", f1, tp)[0]
        vp = tp - soff
        vs, _ = struct.unpack_from("<HH", f1, vp)
        nf = (vs - 4) // 2
        for fi in range(nf):
            fo = struct.unpack_from("<H", f1, vp + 4 + fi*2)[0]
            if fo == 0: continue
            ap = tp + fo
            if ap + 4 > len(f1): continue
            # String fields
            ind = struct.unpack_from("<I", f1, ap)[0]
            tgt = ap + ind
            if 0 < ind < len(f1) and tgt + 4 <= len(f1):
                sl = struct.unpack_from("<I", f1, tgt)[0]
                if 0 < sl < 300 and tgt + 4 + sl <= len(f1):
                    try:
                        s = f1[tgt+4:tgt+4+sl].decode("utf-8")
                        if "Game/Blueprints" in s:
                            m = re.search(r'Player/(\w+)\.', s)
                            info["character"] = m.group(1) if m else s.split("/")[-1]
                        elif re.match(r'\d+\.\d+,', s):
                            parts = s.split("|")
                            if parts:
                                xyz = [float(v) for v in parts[0].split(",")]
                                info["x"], info["y"], info["z"] = xyz[0], xyz[1], xyz[2]
                        elif re.match(r'\d+\.\d+\.\d+\.\d+:\d+', s):
                            info["relay"] = s
                    except: pass
            # uint64 field[7] = UID
            if fi == 7 and ap + 8 <= len(f1):
                uid = struct.unpack_from("<Q", f1, ap)[0]
                if 100_000_000_000 < uid < 999_999_999_999:
                    info["uid"] = uid
    except: pass
    return info


# ════════════════════════════════════════════════════════════════════
#  錨點對齊
# ════════════════════════════════════════════════════════════════════

def find_anchors(dense: bytes) -> list[tuple[int, str]]:
    """
    找固定錨點：UTF-16 LE 字串、固定 magic bytes、已知欄位。
    回傳 [(offset, label), ...]
    """
    anchors = []

    # 1. UTF-16 字串錨點
    known_utf16 = [
        b"C\x00u\x00s\x00t\x00o\x00m\x00I\x00c\x00o\x00n",   # CustomIcon
        b"F\x00i\x00l\x00t\x00e\x00r\x00S\x00t\x00a\x00t",   # FilterState
        b"S\x00e\x00a\x00r\x00c\x00h\x00T\x00y\x00p",        # SearchType
        b"G\x00T\x00e\x00s\x00t",                             # GTest
        b"L\x00i\x00k\x00e\x00p\x00r\x00i\x00c\x00e",        # Likeprice
    ]
    for pattern in known_utf16:
        pos = dense.find(pattern)
        if pos >= 0:
            label = pattern.replace(b'\x00', b'').decode('ascii', errors='replace')
            anchors.append((pos, f"utf16:{label}"))

    # 2. Fixed 2-byte pattern 0x88 0x01（在 header 附近固定出現）
    pos = 0
    count = 0
    while True:
        pos = dense.find(b'\x88\x01', pos)
        if pos < 0 or count > 5: break
        anchors.append((pos, f"magic_0x8801_{count}"))
        pos += 2; count += 1

    # 3. Player UID as uint64 LE（可能出現在 dense zone）
    uid_bytes = struct.pack("<Q", 218210397178)
    pos = dense.find(uid_bytes)
    if pos >= 0:
        anchors.append((pos, "player_uid_u64"))

    return sorted(anchors, key=lambda x: x[0])


def compute_alignment_shift(dense_a: bytes, dense_b: bytes) -> int:
    """
    計算兩份 Dense Zone 的對齊偏移量。
    嘗試找到一個 shift 使相同錨點對齊。
    回傳 shift (b 相對於 a 需要向右移多少 bytes，可為負)
    """
    anchors_a = {label: off for off, label in find_anchors(dense_a)}
    anchors_b = {label: off for off, label in find_anchors(dense_b)}

    shifts = []
    for label in anchors_a:
        if label in anchors_b:
            shift = anchors_b[label] - anchors_a[label]
            shifts.append(shift)

    if not shifts:
        return 0  # 無錨點，假設對齊
    # 取眾數 shift
    return Counter(shifts).most_common(1)[0][0]


# ════════════════════════════════════════════════════════════════════
#  型別解碼
# ════════════════════════════════════════════════════════════════════

GAME_VALUE_RANGES = {
    "hp":        (0,    100_000),
    "energy":    (0,    10_000),
    "coord":     (-500_000, 500_000),
    "cd_ms":     (0,    120_000),
    "level":     (1,    100),
    "item_count":(0,    9999),
}

def decode_typed(data: bytes, offset: int) -> dict:
    """在 offset 處嘗試所有常見遊戲型別解碼"""
    results = {}
    if offset + 4 <= len(data):
        raw4 = data[offset:offset+4]
        results["u32"] = struct.unpack_from("<I", raw4)[0]
        results["i32"] = struct.unpack_from("<i", raw4)[0]
        results["f32"] = struct.unpack_from("<f", raw4)[0]
        results["u16_lo"] = struct.unpack_from("<H", raw4)[0]
        results["u16_hi"] = struct.unpack_from("<H", raw4, 2)[0]
    if offset + 8 <= len(data):
        raw8 = data[offset:offset+8]
        results["u64"]  = struct.unpack_from("<Q", raw8)[0]
        results["f64"]  = struct.unpack_from("<d", raw8)[0]
    results["hex4"] = data[offset:offset+4].hex() if offset+4 <= len(data) else ""
    return results


def guess_field_type(val_a: dict, val_b: dict) -> str:
    """根據兩份數值猜測最可能的型別"""
    for key in ["f32", "i32", "u32"]:
        va = val_a.get(key, 0)
        vb = val_b.get(key, 0)
        if key == "f32":
            if not (math.isnan(va) or math.isinf(va) or
                    math.isnan(vb) or math.isinf(vb)):
                if -500_000 < va < 500_000 and -500_000 < vb < 500_000:
                    if va != vb:
                        return "f32"
        elif key in ("i32", "u32"):
            if 0 <= va <= 1_000_000 and 0 <= vb <= 1_000_000 and va != vb:
                return key
    return "u32"


# ════════════════════════════════════════════════════════════════════
#  快照資料庫
# ════════════════════════════════════════════════════════════════════

def load_db() -> dict:
    if os.path.exists(SNAPSHOT_DB):
        with open(SNAPSHOT_DB, "r", encoding="utf-8") as f:
            db = json.load(f)
            # Restore bytes from hex
            for tag, snap in db.items():
                if isinstance(snap.get("dense_hex"), str):
                    snap["dense"] = bytes.fromhex(snap["dense_hex"])
            return db
    return {}


def save_db(db: dict):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    serializable = {}
    for tag, snap in db.items():
        s = dict(snap)
        if isinstance(s.get("dense"), bytes):
            s["dense_hex"] = s.pop("dense").hex()
        serializable[tag] = s
    with open(SNAPSHOT_DB, "w", encoding="utf-8") as f:
        json.dump(serializable, f, ensure_ascii=False, indent=2, default=str)


def add_snapshot(pcap_path: str, tag: str):
    print(f"[*] 讀取 {pcap_path} → tag={bold(tag)}")
    streams = reassemble(pcap_path)
    dense, meta = extract_dense_zone(streams)
    if dense is None:
        print(red("[!] 找不到 Dense Zone，請確認 Target IP 正確"))
        return

    db = load_db()
    db[tag] = {
        "pcap":   pcap_path,
        "tag":    tag,
        "meta":   meta,
        "dense":  dense,
        "anchors": find_anchors(dense),
    }
    save_db(db)

    player = meta.get("player", {})
    print(f"[✓] 已儲存快照 '{tag}'")
    print(f"    Dense Zone: {len(dense)} bytes")
    print(f"    Character:  {player.get('character', 'unknown')}")
    print(f"    Position:   x={player.get('x',0):.0f} y={player.get('y',0):.0f} z={player.get('z',0):.0f}")
    print(f"    UID:        {player.get('uid', 'unknown')}")
    anchors = find_anchors(dense)
    print(f"    Anchors:    {len(anchors)} found → {[a[1] for a in anchors[:4]]}")


# ════════════════════════════════════════════════════════════════════
#  核心差異分析
# ════════════════════════════════════════════════════════════════════

def diff_snapshots(tag_a: str, tag_b: str,
                   threshold: int = 4,
                   window: int = 4,
                   max_results: int = 200,
                   csv_path: str | None = None):

    db = load_db()
    if tag_a not in db or tag_b not in db:
        missing = [t for t in [tag_a, tag_b] if t not in db]
        print(red(f"[!] 找不到快照：{missing}"))
        print(f"    現有快照：{list(db.keys())}")
        return

    snap_a = db[tag_a]
    snap_b = db[tag_b]
    dense_a: bytes = snap_a["dense"]
    dense_b: bytes = snap_b["dense"]

    # 對齊
    shift = compute_alignment_shift(dense_a, dense_b)
    if shift != 0:
        print(yellow(f"[!] 偵測到對齊偏移 shift={shift}，自動補正"))
        if shift > 0:
            dense_b = dense_b[shift:]
            dense_a = dense_a[:len(dense_b)]
        else:
            dense_a = dense_a[-shift:]
            dense_b = dense_b[:len(dense_a)]

    comp_len = min(len(dense_a), len(dense_b))

    print(bold("=" * 70))
    print(bold(f"  Dense Zone Diff: '{tag_a}'  vs  '{tag_b}'"))
    pa = snap_a["meta"].get("player", {})
    pb = snap_b["meta"].get("player", {})
    print(f"  A: char={pa.get('character','?')}  "
          f"x={pa.get('x',0):.0f} y={pa.get('y',0):.0f} z={pa.get('z',0):.0f}")
    print(f"  B: char={pb.get('character','?')}  "
          f"x={pb.get('x',0):.0f} y={pb.get('y',0):.0f} z={pb.get('z',0):.0f}")
    print(f"  比對長度: {comp_len} bytes  (shift={shift})")
    print(bold("=" * 70))

    # 找所有變動區間
    changed_offsets = [i for i in range(comp_len) if dense_a[i] != dense_b[i]]
    total_changed = len(changed_offsets)
    pct = total_changed / comp_len * 100
    print(f"\n  變動 bytes: {total_changed} / {comp_len} ({pct:.1f}%)")

    # 找 4-byte 對齊的有趣欄位（window=4 連續 bytes 都不同）
    interesting = []
    seen = set()
    for off in changed_offsets:
        base = (off // window) * window
        if base in seen: continue
        if base + window > comp_len: continue
        chunk_a = dense_a[base:base+window]
        chunk_b = dense_b[base:base+window]
        if chunk_a == chunk_b: continue
        # All bytes in window differ
        if sum(1 for a, b in zip(chunk_a, chunk_b) if a != b) >= threshold:
            seen.add(base)
            val_a = decode_typed(dense_a, base)
            val_b = decode_typed(dense_b, base)
            ftype = guess_field_type(val_a, val_b)
            va = val_a.get(ftype, 0)
            vb = val_b.get(ftype, 0)
            interesting.append({
                "offset":  base,
                "hex_a":   chunk_a.hex(),
                "hex_b":   chunk_b.hex(),
                "type":    ftype,
                "val_a":   va,
                "val_b":   vb,
                "delta":   (vb - va) if isinstance(va, (int, float)) else "?",
                "all_types_a": val_a,
                "all_types_b": val_b,
            })

    # 按 delta 絕對值排序（最大變化在前）
    interesting.sort(key=lambda x: abs(x["delta"]) if isinstance(x["delta"], (int, float)) else 0, reverse=True)

    # 候選 HP/Energy/CD 欄位（根據合理的遊戲數值範圍過濾）
    hp_candidates      = [r for r in interesting if _looks_like(r, "hp")]
    energy_candidates  = [r for r in interesting if _looks_like(r, "energy")]
    coord_candidates   = [r for r in interesting if _looks_like(r, "coord")]

    # ── 輸出分類結果 ────────────────────────────────────────────────
    _print_section("HP 候選欄位", hp_candidates, tag_a, tag_b)
    _print_section("能量候選欄位", energy_candidates, tag_a, tag_b)
    _print_section("座標候選欄位", coord_candidates, tag_a, tag_b)

    # ── 完整 TOP 差異列表 ──────────────────────────────────────────
    print(f"\n{bold('── 所有變動欄位 TOP ' + str(min(max_results, len(interesting))))} ──")
    print(f"  {'offset':>7}  {'type':5}  {tag_a:>15}  {tag_b:>15}  {'delta':>12}  hex_A         hex_B")
    print("  " + "-"*80)
    for r in interesting[:max_results]:
        va = r["val_a"]
        vb = r["val_b"]
        delta = r["delta"]
        # Colour by magnitude
        if isinstance(delta, float):
            va_s = f"{va:15.3f}"
            vb_s = f"{vb:15.3f}"
            d_s  = f"{delta:+12.3f}"
        else:
            va_s = f"{va:15d}"
            vb_s = f"{vb:15d}"
            d_s  = f"{delta:+12d}" if isinstance(delta, int) else f"{'?':>12}"
        row = f"  {r['offset']:7d}  {r['type']:<5}  {va_s}  {vb_s}  {d_s}  {r['hex_a']}  {r['hex_b']}"
        if abs(delta) > 1000 if isinstance(delta, (int,float)) else False:
            print(yellow(row))
        else:
            print(row)

    # ── CSV 輸出 ────────────────────────────────────────────────────
    if csv_path:
        _write_csv(csv_path, interesting, tag_a, tag_b)
        print(f"\n[*] CSV 儲存至：{bold(csv_path)}")

    # ── 熱力圖（ASCII）───────────────────────────────────────────────
    _print_heatmap(dense_a, dense_b, comp_len)

    print(f"\n[*] 共找到 {len(interesting)} 個變動欄位")
    print(dim("提示：搭配遊戲內即時數值肉眼比對。建議每次只改變一個變數（只掉血/只用技能）再重錄。"))


def _looks_like(r: dict, category: str) -> bool:
    va = r["val_a"]
    vb = r["val_b"]
    if not isinstance(va, (int, float)) or not isinstance(vb, (int, float)):
        return False
    if math.isnan(va) or math.isnan(vb) or math.isinf(va) or math.isinf(vb):
        return False
    ranges = {
        "hp":     ((0, 200_000), (0, 200_000)),
        "energy": ((0, 10_000),  (0, 10_000)),
        "coord":  ((-400_000, 400_000), (-400_000, 400_000)),
    }
    lo, hi = ranges[category][0]
    return (lo <= va <= hi and lo <= vb <= hi and va != vb)


def _print_section(title: str, candidates: list, tag_a: str, tag_b: str):
    if not candidates:
        return
    print(f"\n{bold('── ' + title + ' ──')} ({len(candidates)} 個)")
    print(f"  {'offset':>7}  {'type':5}  {tag_a:>15}  {tag_b:>15}  {'delta':>12}")
    for r in candidates[:15]:
        va, vb, d = r["val_a"], r["val_b"], r["delta"]
        if isinstance(va, float):
            line = f"  {r['offset']:7d}  {r['type']:<5}  {va:15.2f}  {vb:15.2f}  {d:+12.2f}"
        else:
            line = f"  {r['offset']:7d}  {r['type']:<5}  {va:15d}  {vb:15d}  {d:+12d}"
        print(green(line))


def _write_csv(path: str, records: list, tag_a: str, tag_b: str):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["offset", "type", f"val_{tag_a}", f"val_{tag_b}", "delta",
                    f"hex_{tag_a}", f"hex_{tag_b}",
                    "u32_a", "i32_a", "f32_a", "u32_b", "i32_b", "f32_b"])
        for r in records:
            at = r["all_types_a"]
            bt = r["all_types_b"]
            w.writerow([
                r["offset"], r["type"], r["val_a"], r["val_b"], r["delta"],
                r["hex_a"], r["hex_b"],
                at.get("u32",""), at.get("i32",""), at.get("f32",""),
                bt.get("u32",""), bt.get("i32",""), bt.get("f32",""),
            ])


def _print_heatmap(dense_a: bytes, dense_b: bytes, comp_len: int):
    """ASCII 熱力圖：每個 cell 代表 512 bytes 的差異密度"""
    CELL = 512
    COLS = 40
    cells = comp_len // CELL
    print(f"\n{bold('── Dense Zone 差異熱力圖')} （每格={CELL}B，共{cells}格）")
    print("  ░=熱度低  ▒=中  ▓=高  █=極高")
    line = "  "
    for i in range(cells):
        start = i * CELL
        end   = start + CELL
        chunk_a = dense_a[start:end]
        chunk_b = dense_b[start:end]
        n_diff = sum(1 for a, b in zip(chunk_a, chunk_b) if a != b)
        ratio = n_diff / CELL
        if   ratio < 0.25: ch = "░"
        elif ratio < 0.50: ch = "▒"
        elif ratio < 0.75: ch = "▓"
        else:               ch = "█"
        line += ch
        if (i + 1) % COLS == 0:
            print(line)
            line = "  "
    if line.strip():
        print(line)
    # Offset scale
    scale = "  "
    for i in range(0, cells, 10):
        label = f"{i*CELL//1024}K"
        scale += label + " " * (10 - len(label))
    print(scale[:2 + COLS])


# ════════════════════════════════════════════════════════════════════
#  單份探索模式
# ════════════════════════════════════════════════════════════════════

def explore_snapshot(tag: str, offset: int = 0, length: int = 256):
    """顯示指定 offset 的 hex dump + 多型別解碼"""
    db = load_db()
    if tag not in db:
        print(red(f"[!] 找不到快照 '{tag}'"))
        return
    dense = db[tag]["dense"]
    end = min(offset + length, len(dense))
    print(bold(f"── Dense Zone 探索: '{tag}' offset={offset} ──"))
    print(f"  {'offset':>6}  {'hex':47}  {'ascii':16}")
    for i in range(offset, end, 16):
        chunk = dense[i:i+16]
        hx  = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:6d}  {hx:<47}  {asc}")

    print(f"\n  多型別解碼 (4-byte 對齊，offset={offset} 開始的前 64 bytes):")
    print(f"  {'off':>6}  {'u32':>12}  {'i32':>12}  {'f32':>14}  {'u16lo':>6}  {'u16hi':>6}  hex")
    for i in range(offset, min(offset+64, len(dense)), 4):
        if i + 4 > len(dense): break
        u32 = struct.unpack_from("<I", dense, i)[0]
        i32 = struct.unpack_from("<i", dense, i)[0]
        f32 = struct.unpack_from("<f", dense, i)[0]
        h16 = struct.unpack_from("<H", dense, i)[0]
        h17 = struct.unpack_from("<H", dense, i+2)[0]
        raw = dense[i:i+4].hex()
        f32_s = f"{f32:14.4f}" if not (math.isnan(f32) or math.isinf(f32) or abs(f32) > 1e10) else f"{'(invalid)':>14}"
        print(f"  {i:6d}  {u32:12d}  {i32:12d}  {f32_s}  {h16:6d}  {h17:6d}  {raw}")


# ════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════

def main():
    global TARGET_IP
    parser = argparse.ArgumentParser(
        description="NTE Dense Zone Differ — 找出 HP/能量/CD 等即時數值欄位",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用範例：
  # Step 1：滿血狀態錄製
  python dense_zone_differ.py --add full_hp.pcap --tag full_hp

  # Step 2：殘血狀態錄製
  python dense_zone_differ.py --add low_hp.pcap --tag low_hp

  # Step 3：比對，輸出 CSV
  python dense_zone_differ.py --diff full_hp low_hp --csv diff_hp.csv

  # 探索特定 offset
  python dense_zone_differ.py --explore full_hp --offset 2165 --length 128

  # 查看所有快照
  python dense_zone_differ.py --list

建議錄製組合：
  full_hp  vs  low_hp        → 找 HP 欄位
  full_en  vs  empty_en      → 找能量欄位
  pos_A    vs  pos_B         → 找座標欄位（移動到不同位置）
  cd_ready vs  cd_cooldown   → 找技能 CD 欄位
"""
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--add",     metavar="PCAP",  help="新增快照")
    group.add_argument("--diff",    nargs=2,          metavar=("TAG_A","TAG_B"), help="比對兩份快照")
    group.add_argument("--explore", metavar="TAG",    help="探索快照的 hex dump")
    group.add_argument("--list",    action="store_true", help="列出所有快照")

    parser.add_argument("--tag",       default="snapshot",  help="快照標籤（搭配 --add）")
    parser.add_argument("--offset",    type=int, default=0,   help="起始 offset（搭配 --explore）")
    parser.add_argument("--length",    type=int, default=256,  help="顯示長度（搭配 --explore）")
    parser.add_argument("--threshold", type=int, default=3,    help="最少幾個 bytes 不同才算有效欄位")
    parser.add_argument("--top",       type=int, default=100,  help="顯示前 N 個變動欄位")
    parser.add_argument("--csv",       metavar="PATH",         help="輸出 CSV 路徑")
    parser.add_argument("--ip",        default=TARGET_IP,      help=f"目標 IP（預設 {TARGET_IP}）")

    args = parser.parse_args()

    # Override target IP if specified
    TARGET_IP = args.ip

    if args.add:
        add_snapshot(args.add, args.tag)

    elif args.diff:
        csv_out = args.csv or os.path.join(OUTPUT_DIR, f"dense_diff_{args.diff[0]}_vs_{args.diff[1]}.csv")
        diff_snapshots(
            args.diff[0], args.diff[1],
            threshold=args.threshold,
            max_results=args.top,
            csv_path=csv_out,
        )

    elif args.explore:
        explore_snapshot(args.explore, offset=args.offset, length=args.length)

    elif args.list:
        db = load_db()
        if not db:
            print("[*] 尚無快照，請先用 --add 新增")
            return
        print(bold(f"── 快照列表（共 {len(db)} 份）──"))
        for tag, snap in db.items():
            p = snap.get("meta", {}).get("player", {})
            print(f"  {cyan(tag):<20}  char={p.get('character','?'):<30}  "
                  f"x={p.get('x',0):.0f} y={p.get('y',0):.0f} z={p.get('z',0):.0f}  "
                  f"dense={snap.get('meta',{}).get('dense_bytes',0)}B  "
                  f"pcap={snap.get('pcap','?')}")


if __name__ == "__main__":
    main()