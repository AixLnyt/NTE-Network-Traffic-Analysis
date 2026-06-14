# NTE Network Traffic Analysis

逆向工程 **異環 (Neverness to Everness)** 的私有遊戲通訊協定。透過 PCAP 流量捕獲與 Python 靜態分析，還原協定結構、序列化格式、玩家狀態資料與任務系統。

> **免責聲明**：本專案純屬個人離線靜態分析，所有資料均來自本機自錄的 PCAP，不涉及任何伺服器攻擊、封包注入、認證憑證解密或網路干擾行為。

---

## 目錄結構

```
C:\Users\User\Desktop\py\pcap\
│
├── nte_decoder_v3.py         ← 主程式：完整 PCAP 解碼流程
├── dense_zone_differ.py      ← 工具：Dense Zone 多份 PCAP 差異比對
├── frame_decoder.py          ← 工具：單一 frame hex 逐欄位解析
├── export_frames.py          ← 工具：從 pcap 匯出所有 frame hex
├── record_extractor.py       ← 工具：quest record 分類提取與噪音過濾
│
├── frames.txt                (export_frames.py 產生)
├── nte_player_info.txt       (nte_decoder_v3.py 產生)
├── nte_quests_v3.csv         (nte_decoder_v3.py 產生)
├── nte_decoded_v3.json       (nte_decoder_v3.py 產生)
├── categorized_records.csv   (record_extractor.py 產生)
└── dense_snapshots.json      (dense_zone_differ.py 快照資料庫)
```

---

## 快速開始

```bash
pip install scapy

# 完整解碼一份 PCAP
python nte_decoder_v3.py test01.pcap 34.110.242.50

# 只看任務/物品記錄
python record_extractor.py test01.pcap 34.110.242.50

# Dense Zone 差異比對（找 HP/能量/CD）
python dense_zone_differ.py --add full_hp.pcap --tag full_hp
python dense_zone_differ.py --add low_hp.pcap  --tag low_hp
python dense_zone_differ.py --diff full_hp low_hp --csv hp_diff.csv

# 匯出 frame hex 逐一解析
python export_frames.py test01.pcap 34.110.242.50 frames.txt
python frame_decoder.py --file frames.txt
```

---

## 協定逆向分析結果

### 傳輸層

| 項目 | 值 |
|---|---|
| 傳輸協定 | TCP |
| 目標伺服器 | `34.110.242.50:30031`（GCP 亞洲節點） |
| TLS | 有（OS 層解密，payload 本身無應用層加密） |
| Relay server | `34.146.x.x:302xx`（房間/地圖實例，per-session） |

### 封包格式（Framing）

```
┌────────────────────────────────────────────────────────┐
│  4 bytes (LE uint32)  │  Frame Payload                 │
│      length field      │  (FlatBuffers 或自定義二進位) │
└────────────────────────────────────────────────────────┘
```

連線建立後的世界狀態幀（Frame 4）**沒有** length prefix，直接在 LE4 framing 中斷點後開始。

---

### Frame 結構（每次連線固定順序）

#### Frame 1 — 連線初始化（~200 bytes）

格式：FlatBuffers

| 欄位 | 範例值 | 說明 |
|---|---|---|
| server IP | `35.191.x.x` | GCP Load Balancer anycast IP |
| build date | `20200704` | 伺服器 build hash |
| session token | 4-5 字元亂碼 | per-session 隨機 token |
| field[0] u32 | `1117/1120` | message counter（每幀遞增）|

#### Frame 2 — 玩家狀態快照（~392–400 bytes）

格式：FlatBuffers，內含一個 nested table（14 個欄位）

| 欄位 | 範例值 | 含義 |
|---|---|---|
| field[0] | `1510030 / 1904370 / 786916` | Actor network handle（per-session）|
| **field[1]** | `1009876543  (10位數，範例值)` | **Perfect World SDK 內部帳號 ID**（跨 session/角色固定，非遊戲 UID）|
| field[2] | `284–304` | 不明 scalar |
| field[3] | `TagOthers` | Actor tag |
| field[4] | `34.x.x.x:302xx` | Relay server（per-session）|
| field[5] | 座標字串 | `X,Y,Z\|Pitch,Yaw,Roll\|ScaleX,Y,Z` |
| field[6] | `160–168` | 不明 scalar |
| **field[7]** | `123456789012  (12位數，範例值)` | **✅ 玩家遊戲 UID**（uint64 LE，已透過遊戲內截圖驗證）|
| field[8] | blueprint path | 角色藍圖路徑（含角色名）|
| field[11] | `1` | active flag |
| field[12] | `75777 / 77825` | Zone / Map Instance ID（隨地圖變化）|
| field[13] | `0xCDCDCDCD` | 未初始化欄位（MSVC debug heap fill pattern，伺服器未設定）|

> **重要修正**：field[7] 之前誤判為 uint32 nonce（`0xCE5A6BFA` = 3462032378），實際應讀取為 **uint64 LE**（後 4 bytes `32 00 00 00`），完整值為 `123456789012  (12位數，範例值)`，即玩家的遊戲內 UID。

#### Frame 3 — 心跳 / Tick 同步（72 bytes）

格式：FlatBuffers，vtable 結構與 Frame 1 相同，field[0] 值遞增（message counter），entropy 極低（~3.2），確認為心跳包。

#### Frame 4 — 遊戲世界狀態（~90–130 KB，視場景而定）

格式：自定義二進位，分兩個固定大小子區域：

```
Frame 4
├── Dense Zone  [0 : 40960]    固定 40960 bytes
│   ├── Header     [0 : 2560]   跨 session 完全靜態（連線 metadata，與玩家狀態無關）
│   └── Entity 陣列 [2560:40960] 動態長度記錄陣列（怪物/隊友/掉落物/裝飾品）
│       └── PrivateSpawnInfoRecord  以玩家 UID 標記的裝飾品擺放記錄
│
└── Sparse Zone [40960 : end]  Quest/Item/社交字串記錄表（長度隨場景變化）
    ├── FlatBuffers header      root_offset=16，3 個欄位
    ├── Quest/Item Record array  見下方格式
    └── 副本場景額外資料
        ├── "Gameplay will be recorded" 系統訊息（反作弊提示）
        ├── 隊伍成員社交資料（暱稱/GUID/裝飾框）— 範圍外，未深入解析
        └── 32 字元 hex GUID（角色/物品實例 ID）
```

---

### Quest Record 格式（Sparse Zone）

每筆 record 的完整 binary layout：

```
offset  size  型別      說明
+0      1B    uint8     padding
+1      4B    uint32    type_a（任務狀態類型）
+5      4B    uint32    type_b（任務子類型 / 分類代碼）
+9      4B    uint32    unknown_C
+13     4B    uint32    str_bytelen（UTF-16 bytes + 2-byte null）
+17     N     UTF-16LE  任務/物品名稱字串
+17+N   2B    null      字串結尾 \0\0
+17+N+2 7B    混合      val_a(4B) + val_b(2B) + pad(1B)
```

**type_b 分類代碼對照：**

| type_b | 分類 |
|---|---|
| 3 | 戰鬥獎勵任務 (Combat Award Quest) |
| 5 | 新手目標 (Newbie Goals) |
| 6 | 每日任務 |
| 7 | 釣魚等級獎勵 |
| 8 | 釣魚圖鑑 |
| 9 | 活動綁定任務 (Op Activity Bond) |
| 11 | 城市活動任務 |
| 12 | 社交/貝果任務 (Bagel System) |
| 13 | 覺醒系統 |
| 15 | 神秘島 |
| 22 | 道具庫存 |

---

## 各 PCAP 樣本對照

| PCAP | 角色 | 座標 | Zone ID | Sparse Zone 大小 | 備註 |
|---|---|---|---|---|---|
| test01 | Player_004_Lacrimosa | (-146236, 121043, 7105) | — | ~56KB | 第一份樣本，Frame4 截斷 |
| test02 | player_010_nanally | (17140~17672, 144226~144400, 8456) | 75777/77825 | ~56KB | 402 筆 quest record |
| test03 | Player_004_Lacrimosa | (38534, 134776, 3591) | 77825 | ~56KB | 登入流程，含 pwsdk.com API 列表 |
| test04 | Player_004_Lacrimosa | (38534, 134776, 3591) | 75777 | ~87KB | 監獄副本，新增 Prison quest 系列 |

跨 session 固定值：**UID `123456789012  (12位數，範例值)`**、**SDK帳號ID `1009876543  (10位數，範例值)`**、field[13] debug fill `0xCDCDCDCD`

---

## 腳本說明

### `nte_decoder_v3.py` — 主程式

完整端到端解碼流程，一個指令輸出三份報告。

```
用法：python nte_decoder_v3.py <pcap_file> [target_ip]

輸出：
  nte_player_info.txt   Frame 0/1 的連線資訊（IP、角色、座標、UID）
  nte_quests_v3.csv     所有 quest/item record（名稱、類型、進度值）
  nte_decoded_v3.json   完整結構化 JSON
```

**CSV 欄位：**

| 欄位 | 說明 |
|---|---|
| quest_name | 任務/物品識別字串 |
| category | 自動分類（fishing / quest / item / ui_redpoint / world_object）|
| type_a | 狀態碼（1=進行中, 3=已完成）|
| type_b | 分類代碼（見上表）|
| val_a | 當前進度值 |
| val_b | 目標值（val_a == val_b = 完成）|

---

### `dense_zone_differ.py` — Dense Zone 差異分析

```
用法：
  python dense_zone_differ.py --add <pcap> --tag <標籤>            新增快照
  python dense_zone_differ.py --diff <tagA> <tagB> --csv out.csv  比對
  python dense_zone_differ.py --explore <tag> --offset N --length L  hex dump
  python dense_zone_differ.py --list                               列出所有快照
```

**目前已知：**
- Dense Zone 固定 40960 bytes
- `[0:2560]` Header 區跨 session **完全靜態**，不含玩家狀態
- `[2560:40960]` 為動態 entity 陣列，長度隨場景內物件數量變化，直接 diff 容易被雜訊淹沒

**建議錄製方式（提高 diff 訊號比）：**
1. 在**同一個場景/同一個 entity 陣列狀態**下錄兩次
2. 兩次之間只改變一個變數（例如「被打一拳」掉血）
3. 間隔時間越短越好，避免怪物/隊友進出造成陣列變動

---

### `record_extractor.py` — 任務記錄提取器

帶分類標籤的精簡版提取工具。

```
用法：python record_extractor.py <pcap_file> [target_ip]
輸出：categorized_records.csv / categorized_records.json
```

---

### `export_frames.py` + `frame_decoder.py`

```
python export_frames.py <pcap_file> [target_ip] [output_txt]
python frame_decoder.py --file frames.txt
python frame_decoder.py <hex_string>
```

---

## 如何錄製 PCAP

**必做設定：**
```
Wireshark → Edit → Preferences → Capture → Default capture snaplen = 0
```

**一般場景：**
1. 捕獲過濾器：`host 34.110.242.50`
2. 進入地圖，等載入完成後再多等 10 秒才停止錄製

**Dense Zone diff 專用：**
- 同場景錄兩次，中間只改變一個數值狀態（HP/能量/CD）
- 間隔越短越好

---

## 已知限制 / 待研究

- **Dense Zone entity 陣列**：`[2560:40960]` 結構未解，含怪物/隊友/掉落物/裝飾品的混合記錄，需要受控環境下的短間隔 diff 才能定位 HP/能量/CD 等個人數值
- **field[2] / field[6]**：Frame 2 中兩個不明 scalar（範圍 160-304），含義未知
- **field[12] Zone ID**：對應關係已確認隨地圖變化，但完整地圖 ID 對照表未建立
- **TLS 層**：`mapi.pwsdk.com` 等認證 API 全程加密，不在本專案分析範圍內
- **隊伍社交資料區**：副本場景的 Sparse Zone 內含其他玩家的暱稱/GUID/帳號層級 ID，本專案不解析此區段

---

## 環境需求

```
Python 3.10+
scapy
```

```bash
pip install scapy
```