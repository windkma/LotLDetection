"""Export windows and linux commands grouped cleanly by tool and label for human inspection.
Leaves raw datasets completely unchanged to preserve train/test splits.
"""
import re
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.features.rules_constants import (
    ADDED_WINDOWS_BINARIES, WINDOWS_COMMANDS,
    ADDED_LINUX_BINARIES, LINUX_COMMANDS
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def build_tool_set(binaries, commands):
    known = set()
    for b in list(binaries) + list(commands):
        name = str(b).replace("\\", "/").rsplit("/", 1)[-1].lower()
        name = re.sub(r"\.(?:exe|com|bat|cmd|vbs|ps1)$", "", name)
        if len(name) > 1:
            known.add(name)
    return known

def make_extractor(known_tools):
    sorted_tools = sorted(known_tools, key=lambda x: -len(x))
    def extract_tool(cmd):
        cmd_str = str(cmd).strip().strip('"').strip("'")
        # 1. Check first token/binary name
        parts = cmd_str.split(None, 1)
        if parts:
            first = parts[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
            clean_first = re.sub(r"\.(?:exe|com|bat|cmd|vbs|ps1)$", "", first)
            if clean_first in known_tools:
                return clean_first
        # 2. Check anywhere in command string
        for t in sorted_tools:
            if re.search(rf"\b{re.escape(t)}(?:\.(?:exe|com|bat|cmd|vbs|ps1))?\b", cmd_str, re.IGNORECASE):
                return t
        return "other_system"
    return extract_tool

def export_grouped():
    # Process Windows
    win_tools = build_tool_set(ADDED_WINDOWS_BINARIES, WINDOWS_COMMANDS)
    win_extract = make_extractor(win_tools)
    df_win = pd.read_csv(PROJECT_ROOT / "data" / "raw" / "windows.csv")
    df_win["tool"] = df_win["commands"].apply(win_extract)
    df_win["type"] = df_win["label"].map({1: "BAD (Tấn công)", 0: "GOOD (Lành tính)"})
    
    # Sort by tool alphabetically, then label (1 first, then 0), then commands
    df_win_sorted = df_win.sort_values(by=["tool", "label", "commands"], ascending=[True, False, True])
    df_win_sorted = df_win_sorted[["tool", "label", "type", "commands"]]
    
    csv_out = PROJECT_ROOT / "data" / "windows_commands_grouped.csv"
    df_win_sorted.to_csv(csv_out, index=False, encoding="utf-8-sig")
    print(f"Exported CSV: {csv_out} ({len(df_win_sorted)} rows)")

    # Build an intuitive Markdown book for reading and studying
    md_out = PROJECT_ROOT / "COMMANDS_BY_TOOL.md"
    
    lines = []
    lines.append("# SỔ TAY TRA CỨU CÁC LỆNH THEO TỪNG CÔNG CỤ (LOTL DETECTION)")
    lines.append("\n> **Lưu ý quan trọng về kiến trúc dữ liệu:**")
    lines.append("> File này được trích xuất độc lập từ `data/raw/windows.csv` nhằm mục đích đọc hiểu, học tập và tra cứu.")
    lines.append("> Tập file huấn luyện gốc `data/raw/windows.csv` **được giữ nguyên vẹn 100% thứ tự dòng** để đảm bảo:")
    lines.append("> 1. Phép chia `train_test_split(random_state=42)` không bị lệch phân bố mẫu giữa train và test.")
    lines.append("> 2. Mã băm toàn vẹn `dataset_sha256` của mô hình không bị sai lệch.")
    lines.append("\n---\n")

    # Table of statistics
    stats = df_win.groupby(["tool", "label"]).size().unstack(fill_value=0)
    for col in [0, 1]:
        if col not in stats.columns:
            stats[col] = 0
    stats["total"] = stats[0] + stats[1]
    stats = stats.sort_values(by="total", ascending=False)
    
    lines.append("## BẢNG THỐNG KÊ CÁC CÔNG CỤ NỔI BẬT\n")
    lines.append("| Công cụ (Tool) | 🔴 Số lệnh Tấn công (BAD) | 🟢 Số lệnh Lành tính (GOOD) | Tổng số lệnh |")
    lines.append("| :--- | :---: | :---: | :---: |")
    for tool, row in stats.head(40).iterrows():
        lines.append(f"| **`{tool}`** | {row[1]} | {row[0]} | {row['total']} |")
    lines.append("\n---\n")

    # Grouped details
    lines.append("## DANH SÁCH CHI TIẾT CÁC LỆNH THEO TỪNG CÔNG CỤ\n")
    
    # Priority tools first
    top_focus_tools = [
        "msbuild", "wmic", "certutil", "powershell", "rundll32", "mshta",
        "cscript", "regsvr32", "reg", "cmd", "netsh", "net", "schtasks",
        "sc", "at", "bitsadmin", "curl", "tar", "python", "git"
    ]
    all_grouped_tools = sorted(df_win["tool"].unique())
    # put focus tools first, then rest
    ordered_tools = [t for t in top_focus_tools if t in all_grouped_tools] + [t for t in all_grouped_tools if t not in top_focus_tools]

    for tool in ordered_tools:
        sub = df_win[df_win["tool"] == tool]
        bad_cmds = sub[sub["label"] == 1]["commands"].unique()
        good_cmds = sub[sub["label"] == 0]["commands"].unique()
        
        lines.append(f"### 📦 Công cụ: `{tool}` (Tổng: {len(sub)} lệnh)")
        lines.append(f"- 🔴 **Tấn công (BAD):** {len(bad_cmds)} lệnh")
        lines.append(f"- 🟢 **Lành tính (GOOD):** {len(good_cmds)} lệnh\n")
        
        if len(bad_cmds) > 0:
            lines.append("#### 🔴 Các lệnh Tấn công (BAD):")
            lines.append("```bat")
            for c in bad_cmds:
                lines.append(c)
            lines.append("```\n")
            
        if len(good_cmds) > 0:
            lines.append("#### 🟢 Các lệnh Lành tính (GOOD):")
            # If too many good commands (e.g. 1000s), show first 50 to keep readable
            display_good = good_cmds[:50]
            lines.append("```bat")
            for c in display_good:
                lines.append(c)
            if len(good_cmds) > 50:
                lines.append(f"... (và {len(good_cmds) - 50} lệnh lành tính khác trong file CSV)")
            lines.append("```\n")
            
        lines.append("---\n")

    md_out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Exported Markdown: {md_out}")

if __name__ == "__main__":
    export_grouped()
