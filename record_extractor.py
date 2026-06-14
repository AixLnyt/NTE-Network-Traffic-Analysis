#!/usr/bin/env python3
"""
PCAP 記錄提取器 v3 — 分類標註 + 噪音過濾
==========================================
記錄格式：
    uint32  name_len
    utf16le name[name_len]
    int32   value1   (目前值)
    int32   value2   (目標/上限值)
    int32   value3   (狀態: 1=進行中, 3=已完成, 0/2=其他)
    int32   value4   (分類代碼 Category ID)
    int32   value5   (旗標，通常為0或1)

過濾規則：
    保留 value3 ∈ {0,1,2,3} 且 value4 在已知分類代碼清單中（或 < 100）的記錄。
    這可過濾掉因長字串（如 "Redpoint.*"）造成的解析誤判。

用法：
  python pcap_record_extractor_v3.py [pcap_file] [target_ip]
"""

import sys
import struct
import csv
import json
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("[!] 缺少 scapy：pip install scapy")
    sys.exit(1)


# ── 分類代碼對照表（由實際資料統計歸納）─────────────────────────────────────────
CATEGORY_MAP = {
    1:  "成就 (Achievement)",
    2:  "貨幣/資源消耗 (Currency)",
    3:  "戰鬥獎勵任務 (Combat Award Quest)",
    4:  "稱號/獎盃 (Title)",
    5:  "新手目標 (Newbie Goals)",
    6:  "資源庫存 (Resource Bank)",
    7:  "釣魚等級獎勵 (Fishing Level Reward)",
    8:  "釣魚圖鑑 (Fish Handbook)",
    9:  "城市活動任務 (City Gameplay Quest)",
    10: "能力/Buff (Ability)",
    11: "活動綁定任務 (Op Activity Bond Quest)",
    12: "社交/貝果任務 (Bagel Social Quest)",
    13: "覺醒系統 (Awaken)",
    15: "神秘島 (Mysteries Of Island)",
    22: "道具庫存 (Item Inventory)",
}

STATUS_MAP = {
    0: "未開始/無狀態",
    1: "進行中",
    2: "進行中(類型2)",
    3: "已完成",
}


# ── TCP Stream Reassembly ─────────────────────────────────────────────────────

def reassemble_streams(pcap_path: str, target_ip: str) -> dict:
    pkts = rdpcap(pcap_path)
    stream_pkts = defaultdict(list)
    for pkt in pkts:
        if not (IP in pkt and TCP in pkt):
            continue
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        if src_ip != target_ip and dst_ip != target_ip:
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue
        key = (src_ip, pkt[TCP].sport, dst_ip, pkt[TCP].dport)
        stream_pkts[key].append((pkt[TCP].seq, payload))

    reassembled = {}
    for key, segments in stream_pkts.items():
        segments.sort(key=lambda x: x[0])
        buf = bytearray()
        last_seq = None
        for seq, data in segments:
            if last_seq is None or seq > last_seq:
                buf.extend(data)
                last_seq = seq + len(data)
        reassembled[key] = bytes(buf)
    return reassembled


# ── 記錄提取 ──────────────────────────────────────────────────────────────────

def extract_records(buf: bytes) -> list[dict]:
    records = []
    n = len(buf)
    pos = 0

    while pos + 4 <= n:
        name_len = struct.unpack_from("<I", buf, pos)[0]

        if 2 <= name_len <= 128 and name_len % 2 == 0:
            name_start = pos + 4
            name_end = name_start + name_len
            tail_end = name_end + 20

            if tail_end <= n:
                raw_name = buf[name_start:name_end]
                try:
                    name = raw_name.decode("utf-16-le")
                except UnicodeDecodeError:
                    name = None

                if name is not None:
                    name_clean = name.rstrip("\x00")
                    if name_clean and all(
                        c.isprintable() and ord(c) < 128 for c in name_clean
                    ):
                        v1, v2, v3, v4, v5 = struct.unpack_from("<5i", buf, name_end)
                        records.append({
                            "offset": pos,
                            "name": name_clean,
                            "value1": v1,
                            "value2": v2,
                            "value3": v3,
                            "value4": v4,
                            "value5": v5,
                        })
                        pos += 4 + name_len + 20
                        continue

        pos += 1

    return records


def is_clean_record(r: dict) -> bool:
    """過濾解析誤判的記錄：value3 必須是小的狀態碼，value4 必須是合理的分類代碼"""
    if r["value3"] not in (0, 1, 2, 3):
        return False
    if not (0 <= r["value4"] < 1000):
        return False
    if abs(r["value1"]) > 10_000_000 or abs(r["value2"]) > 10_000_000:
        return False
    return True


def categorize(r: dict) -> dict:
    r = dict(r)
    r["category"] = CATEGORY_MAP.get(r["value4"], f"未知分類({r['value4']})")
    r["status"] = STATUS_MAP.get(r["value3"], f"未知狀態({r['value3']})")
    return r


# ── 主流程 ────────────────────────────────────────────────────────────────────

def main():
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "NTE.pcap"
    target_ip = sys.argv[2] if len(sys.argv) > 2 else "34.110.242.50"

    print("=" * 78)
    print("  PCAP 記錄提取器 v3 — 分類標註 + 噪音過濾")
    print(f"  檔案：{pcap_path}")
    print(f"  目標 IP：{target_ip}")
    print("=" * 78)

    streams = reassemble_streams(pcap_path, target_ip)
    if not streams:
        print(f"[!] 未找到 {target_ip} 的 TCP 流量")
        return

    all_records = []
    for stream_key, raw_data in streams.items():
        src_ip, sport, dst_ip, dport = stream_key
        records = extract_records(raw_data)
        for r in records:
            r["stream"] = f"{src_ip}:{sport}->{dst_ip}:{dport}"
        all_records.extend(records)

    raw_count = len(all_records)
    clean_records = [categorize(r) for r in all_records if is_clean_record(r)]
    noise_count = raw_count - len(clean_records)

    print(f"\n[*] 共掃描出 {raw_count} 筆原始記錄，"
          f"過濾掉 {noise_count} 筆噪音，保留 {len(clean_records)} 筆有效記錄\n")

    # ── 依分類分組顯示 ────────────────────────────────────────────────────────
    by_category = defaultdict(list)
    for r in clean_records:
        by_category[r["category"]].append(r)

    for cat, items in sorted(by_category.items(), key=lambda x: -len(x[1])):
        print(f"── {cat}  ({len(items)} 筆) ──")
        # 只顯示前 8 筆當範例
        for r in items[:8]:
            print(f"    {r['name']:<28} 數值={r['value1']:>8} / "
                  f"上限={r['value2']:>8}  狀態={r['status']}  V5={r['value5']}")
        if len(items) > 8:
            print(f"    ... 共 {len(items)} 筆")
        print()

    # ── 輸出 CSV ──────────────────────────────────────────────────────────────
    csv_path = "C:\\Users\\User\\Desktop\\py\\pcap\\categorized_records.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "stream", "offset", "category", "name", "status",
            "value1", "value2", "value3", "value4", "value5"
        ])
        writer.writeheader()
        for r in clean_records:
            writer.writerow({k: r[k] for k in writer.fieldnames})
    print(f"[*] 分類後 CSV 已儲存至：{csv_path}")

    # ── 輸出 JSON ─────────────────────────────────────────────────────────────
    json_path = "C:\\Users\\User\\Desktop\\py\\pcap\\categorized_records.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(clean_records, f, ensure_ascii=False, indent=2)
    print(f"[*] 分類後 JSON 已儲存至：{json_path}")

    # ── 已完成的任務/成就清單（status=已完成）────────────────────────────────────
    completed = [r for r in clean_records if r["value3"] == 3]
    print(f"\n[*] 狀態=已完成 的記錄共 {len(completed)} 筆")


if __name__ == "__main__":
    main()