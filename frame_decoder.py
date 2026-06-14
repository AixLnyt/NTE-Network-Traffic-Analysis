#!/usr/bin/env python3
"""
30031 Port Frame Decoder — 通用版
====================================
輸入：單一 Frame 的 hex 字串（不含 4-byte 長度前綴，或包含也可自動偵測）
輸出：
  1. Header 解析（opcode / 長度欄位）
  2. FlatBuffers root table 解析（vtable + 欄位數值）
  3. Protobuf-style 盲解（備用：若資料不符合 FlatBuffers，嘗試以
     varint tag + wire_type 方式解析）
  4. 可讀字串掃描（UTF-16LE / UTF-8）

⚠️ 重要說明：
根據先前對同協定的逆向分析，這個協定的封包格式實際上是
**FlatBuffers**，不是標準 Protobuf。FlatBuffers 沒有「varint tag」，
而是使用固定大小的 vtable + offset 結構。
本腳本因此「以 FlatBuffers 解析為主」，但仍保留一個 Protobuf-style
盲解函式作為備用 fallback（當資料不符合 FlatBuffers 結構時嘗試）。

用法：
  python frame_decoder.py <hex_string>
  python frame_decoder.py --file frames.txt   # 每行一個 hex frame

範例：
  python frame_decoder.py c8000000140000000000000000000a000c00...
"""

import sys
import struct
import re


# ──────────────────────────────────────────────────────────────────────────
# 1. Header 解析：opcode / 長度欄位
# ──────────────────────────────────────────────────────────────────────────

def parse_header(data: bytes) -> dict:
    """
    解析封包開頭：
      - 若前 4 bytes 是合理的「剩餘長度」(LE uint32)，視為 framing length
      - 接著的 4 bytes（FlatBuffers buffer 起點）為 root table offset
      - 透過 root table 取得 field[0]，作為 opcode/序列號
    """
    header = {}

    if len(data) < 8:
        header["error"] = "資料太短，無法解析 header"
        return header

    framing_len = struct.unpack_from("<I", data, 0)[0]
    header["framing_length_field"] = framing_len
    header["framing_length_matches"] = (framing_len == len(data) - 4)

    # FlatBuffers buffer 起點：若 framing length 合理，從 offset 4 開始；否則從 0 開始
    fb_start = 4 if header["framing_length_matches"] else 0
    fb = data[fb_start:]
    header["fb_buffer_start"] = fb_start
    header["fb_buffer_len"] = len(fb)

    table = parse_flatbuffer_root_table(fb)
    header["root_table"] = table

    if table:
        # field[0] 在先前分析中觀察到為 opcode（1117/1120/1122）
        f0 = next((f for f in table["fields"] if f["index"] == 0 and f.get("present")), None)
        if f0:
            header["opcode"] = f0.get("i32")
            header["opcode_hex"] = f0.get("raw_hex")

        # field[2]（如有）常為 UOffset，指向巢狀資料（payload主體）
        f2 = next((f for f in table["fields"] if f["index"] == 2 and f.get("present")), None)
        if f2:
            header["field2_uoffset_target"] = f2.get("uoffset_target")

    return header


# ──────────────────────────────────────────────────────────────────────────
# 2. FlatBuffers Root Table 解析
# ──────────────────────────────────────────────────────────────────────────

def parse_flatbuffer_root_table(fb: bytes) -> dict | None:
    if len(fb) < 8:
        return None
    try:
        root_off = struct.unpack_from("<I", fb, 0)[0]
        if root_off + 4 > len(fb) or root_off < 0:
            return None

        vtable_soff = struct.unpack_from("<i", fb, root_off)[0]
        vtable_pos = root_off - vtable_soff
        if vtable_pos < 0 or vtable_pos + 4 > len(fb):
            return None

        vtable_size = struct.unpack_from("<H", fb, vtable_pos)[0]
        object_size = struct.unpack_from("<H", fb, vtable_pos + 2)[0]
        if vtable_size < 4 or vtable_size > 200 or vtable_pos + vtable_size > len(fb):
            return None

        num_fields = (vtable_size - 4) // 2
        fields = []

        for i in range(num_fields):
            voffset = struct.unpack_from("<H", fb, vtable_pos + 4 + i * 2)[0]
            if voffset == 0:
                fields.append({"index": i, "voffset": 0, "present": False})
                continue

            abs_off = root_off + voffset
            entry = {"index": i, "voffset": voffset, "abs_offset": abs_off, "present": True}

            if abs_off + 4 <= len(fb):
                raw4 = fb[abs_off:abs_off+4]
                entry["raw_hex"] = raw4.hex()
                entry["u32"] = struct.unpack_from("<I", fb, abs_off)[0]
                entry["i32"] = struct.unpack_from("<i", fb, abs_off)[0]
                entry["f32"] = struct.unpack_from("<f", fb, abs_off)[0]

                target = abs_off + entry["u32"]
                if 0 <= entry["u32"] < len(fb) and target < len(fb):
                    entry["uoffset_target"] = target
                    if target + 4 <= len(fb):
                        slen = struct.unpack_from("<I", fb, target)[0]
                        if 0 < slen < 256 and target + 4 + slen <= len(fb):
                            sdata = fb[target+4:target+4+slen]
                            try:
                                s = sdata.decode("utf-8")
                                if s.isprintable():
                                    entry["uoffset_string"] = s
                            except Exception:
                                pass

            if abs_off + 8 <= len(fb):
                entry["u64"] = struct.unpack_from("<Q", fb, abs_off)[0]
                entry["i64"] = struct.unpack_from("<q", fb, abs_off)[0]
                entry["f64"] = struct.unpack_from("<d", fb, abs_off)[0]

            if abs_off + 1 <= len(fb):
                entry["u8"] = fb[abs_off]
            if abs_off + 2 <= len(fb):
                entry["u16"] = struct.unpack_from("<H", fb, abs_off)[0]

            fields.append(entry)

        return {
            "root_offset": root_off,
            "vtable_offset": vtable_pos,
            "vtable_size": vtable_size,
            "object_size": object_size,
            "num_fields": num_fields,
            "fields": fields,
        }
    except (struct.error, IndexError):
        return None


# ──────────────────────────────────────────────────────────────────────────
# 3. Protobuf-style 盲解（fallback，僅在 FlatBuffers 解析失敗時使用）
# ──────────────────────────────────────────────────────────────────────────

def decode_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result, shift = 0, 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return result, pos
        if shift >= 64:
            raise ValueError("varint 超過 64 bits")
    raise ValueError("varint 未預期結束")


def protobuf_blind_decode(buf: bytes, depth: int = 0, max_depth: int = 4) -> list[dict]:
    """
    嘗試以 Protobuf wire-format 解析 buf。
    僅辨識 Wire Type 0 (varint) 與 Wire Type 2 (length-delimited)，
    其餘類型視為解析失敗並中止。
    """
    fields = []
    pos = 0
    if depth > max_depth:
        return fields

    while pos < len(buf):
        try:
            tag, pos = decode_varint(buf, pos)
        except (ValueError, IndexError):
            break

        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 0:
            break

        entry = {"field": field_number, "wire_type": wire_type}

        if wire_type == 0:  # varint
            try:
                value, pos = decode_varint(buf, pos)
            except (ValueError, IndexError):
                break
            entry["value"] = value
            entry["value_signed"] = value if value < (1 << 63) else value - (1 << 64)
            entry["value_zigzag"] = (value >> 1) ^ -(value & 1)

        elif wire_type == 2:  # length-delimited
            try:
                length, pos = decode_varint(buf, pos)
            except (ValueError, IndexError):
                break
            if pos + length > len(buf):
                entry["error"] = "length 超出範圍"
                fields.append(entry)
                break
            data = buf[pos:pos+length]
            pos += length
            entry["length"] = length
            entry["raw_hex"] = data.hex()
            try:
                s = data.decode("utf-8")
                if s.isprintable():
                    entry["string"] = s
            except UnicodeDecodeError:
                pass
            if length >= 2:
                nested = protobuf_blind_decode(data, depth + 1, max_depth)
                if nested:
                    entry["nested"] = nested

        else:
            entry["note"] = f"不支援的 wire_type={wire_type}，停止解析"
            fields.append(entry)
            break

        fields.append(entry)

    return fields


# ──────────────────────────────────────────────────────────────────────────
# 4. 字串掃描
# ──────────────────────────────────────────────────────────────────────────

_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_UTF8_RE = re.compile(rb"[\x20-\x7e]{4,}")


def scan_strings(data: bytes) -> list[dict]:
    results = []
    for m in _UTF16_RE.finditer(data):
        try:
            s = m.group(0).decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        results.append({"offset": m.start(), "encoding": "utf-16le", "text": s})

    occupied = [(r["offset"], r["offset"] + len(r["text"]) * 2) for r in results]

    def overlaps(a, b):
        return any(a < e and b > s for s, e in occupied)

    for m in _UTF8_RE.finditer(data):
        if overlaps(m.start(), m.end()):
            continue
        results.append({"offset": m.start(), "encoding": "utf-8",
                         "text": m.group(0).decode("ascii", errors="ignore")})

    results.sort(key=lambda r: r["offset"])
    return results


# ──────────────────────────────────────────────────────────────────────────
# 5. 輸出格式化
# ──────────────────────────────────────────────────────────────────────────

def print_flatbuffer_table(table: dict, indent: int = 1):
    prefix = "  " * indent
    print(f"{prefix}Root table @ {table['root_offset']}  "
          f"(vtable@{table['vtable_offset']} size={table['vtable_size']} "
          f"object_size={table['object_size']} fields={table['num_fields']})")
    for f in table["fields"]:
        if not f.get("present"):
            print(f"{prefix}  field[{f['index']}]: (absent)")
            continue
        line = f"{prefix}  field[{f['index']}] @abs={f['abs_offset']}"
        if "i32" in f:
            line += f"  i32={f['i32']}  u32={f['u32']}"
        if "uoffset_string" in f:
            line += f'  -> string="{f["uoffset_string"]}"'
        elif "uoffset_target" in f:
            line += f"  -> 可能巢狀資料 @{f['uoffset_target']}"
        print(line)


def print_protobuf_fields(fields: list[dict], indent: int = 1):
    prefix = "  " * indent
    for f in fields:
        if "error" in f:
            print(f"{prefix}[!] {f['error']}")
            continue
        if "note" in f:
            print(f"{prefix}[!] {f['note']}")
            continue
        line = f"{prefix}field[{f['field']}] (wire_type={f['wire_type']})"
        if f["wire_type"] == 0:
            line += f"  = {f['value']}  (signed={f['value_signed']}, zigzag={f['value_zigzag']})"
        elif f["wire_type"] == 2:
            line += f"  len={f['length']}"
            if "string" in f:
                line += f'  string="{f["string"]}"'
            else:
                line += f"  hex={f['raw_hex'][:40]}"
        print(line)
        if "nested" in f:
            print(f"{prefix}  └─ nested:")
            print_protobuf_fields(f["nested"], indent + 2)


def print_strings(strings: list[dict], indent: int = 1, max_show: int = 20):
    prefix = "  " * indent
    if not strings:
        print(f"{prefix}(未找到可讀字串)")
        return
    for s in strings[:max_show]:
        txt = s["text"]
        if len(txt) > 80:
            txt = txt[:80] + "..."
        print(f"{prefix}[@{s['offset']:5d}] ({s['encoding']:8s}) {txt!r}")
    if len(strings) > max_show:
        print(f"{prefix}... 共 {len(strings)} 個，已截斷")


# ──────────────────────────────────────────────────────────────────────────
# 6. 主函式：解析單一 Frame
# ──────────────────────────────────────────────────────────────────────────

def decode_frame(hex_str: str):
    hex_str = hex_str.strip().replace(" ", "").replace("\n", "")
    data = bytes.fromhex(hex_str)

    print(f"Frame 長度：{len(data)} bytes")
    print(f"Hex (前64 bytes): {data[:64].hex()}")
    print()

    # ── Header ──
    header = parse_header(data)
    print("[Header]")
    print(f"  framing_length_field = {header.get('framing_length_field')}")
    print(f"  framing_length_matches (len-4) = {header.get('framing_length_matches')}")
    print(f"  fb_buffer_start = {header.get('fb_buffer_start')}, "
          f"fb_buffer_len = {header.get('fb_buffer_len')}")
    if "opcode" in header:
        print(f"  >>> opcode (field[0]) = {header['opcode']}  "
              f"(hex={header['opcode_hex']})")
    print()

    # ── FlatBuffers root table ──
    table = header.get("root_table")
    if table:
        print("[FlatBuffers Root Table]")
        print_flatbuffer_table(table)
    else:
        print("[FlatBuffers 解析失敗 — 嘗試 Protobuf-style 盲解 fallback]")
        fb_start = header.get("fb_buffer_start", 0)
        pb_fields = protobuf_blind_decode(data[fb_start:])
        if pb_fields:
            print_protobuf_fields(pb_fields)
        else:
            print("  (Protobuf 盲解亦無結果，資料可能為非結構化 blob)")
    print()

    # ── 字串掃描 ──
    print("[可讀字串]")
    strings = scan_strings(data)
    print_strings(strings)


# ──────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "--file":
        with open(sys.argv[2], "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                print("=" * 70)
                print(f"  Frame #{i+1}")
                print("=" * 70)
                decode_frame(line)
                print()
    else:
        hex_str = sys.argv[1]
        decode_frame(hex_str)


if __name__ == "__main__":
    main()