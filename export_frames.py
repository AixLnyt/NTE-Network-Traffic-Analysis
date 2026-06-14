#!/usr/bin/env python3
"""
匯出 30031 Frames 為 hex 文字檔
================================
讀取 pcap，重組 TCP stream，依 4-byte LE 長度前綴切分 frame，
將每個 frame 的完整 hex 輸出到 frames.txt（每行一個 frame），
可直接搭配 frame_decoder.py --file frames.txt 使用。

用法：
  python export_frames.py [pcap_file] [target_ip] [output_txt]

範例：
  python export_frames.py NTE.pcap 34.110.242.50 frames.txt
"""

import sys
import struct
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("[!] 缺少 scapy：pip install scapy")
    sys.exit(1)


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


def split_length_prefixed_frames(data: bytes) -> list[bytes]:
    """依 [4-byte LE length][payload] 重複切分；無法切分時整塊回傳"""
    frames = []
    pos = 0
    while pos + 4 <= len(data):
        length = struct.unpack_from("<I", data, pos)[0]
        if length == 0 or pos + 4 + length > len(data) + 8:
            break
        end = pos + 4 + length
        if end > len(data):
            frames.append(data[pos+4:])
            pos = len(data)
            break
        frames.append(data[pos:end])  # 含 4-byte 長度前綴，方便 frame_decoder 自行判斷
        pos = end

    if pos < len(data):
        remainder = data[pos:]
        if remainder:
            frames.append(remainder)

    return frames if frames else [data]


def main():
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "NTE.pcap"
    target_ip = sys.argv[2] if len(sys.argv) > 2 else "34.110.242.50"
    out_path = sys.argv[3] if len(sys.argv) > 3 else "C:\\Users\\User\\Desktop\\py\\pcap\\frames.txt"

    print(f"[*] 讀取 {pcap_path}，目標 IP={target_ip}")
    streams = reassemble_streams(pcap_path, target_ip)
    if not streams:
        print("[!] 找不到該 IP 的 TCP 流量")
        return

    total_frames = 0
    with open(out_path, "w", encoding="ascii") as f:
        for stream_key, raw_data in sorted(streams.items(), key=lambda x: -len(x[1])):
            frames = split_length_prefixed_frames(raw_data)
            f.write(f"# stream {stream_key[0]}:{stream_key[1]} -> {stream_key[2]}:{stream_key[3]}  "
                    f"({len(raw_data)} bytes, {len(frames)} frames)\n")
            for fr in frames:
                f.write(fr.hex() + "\n")
            total_frames += len(frames)

    print(f"[*] 共輸出 {total_frames} 個 frame 到 {out_path}")
    print(f"[*] 接著可執行：python frame_decoder.py --file {out_path}")
    print(f"    （'#' 開頭的行是註解，frame_decoder.py 會自動忽略空行，但請注意註解行需手動跳過或刪除）")


if __name__ == "__main__":
    main()