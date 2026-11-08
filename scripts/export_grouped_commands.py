"""Export windows and linux commands grouped cleanly by tool and label for human inspection.
Output CSV format:
  label,commands
Where label is 1/0 at the beginning, followed by comma, then the command.
Commands are grouped together by tool cluster.
"""
import re
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.tokenizer import extract_executable_tokens

SHELL_WRAPPERS_WIN = {"cmd", "powershell", "pwsh", "wsl", "bash"}
SHELL_WRAPPERS_LINUX = {"sh", "bash", "dash", "zsh", "sudo", "doas", "nohup", "nice", "xargs", "eval", "exec"}

def extract_tool_windows(cmd: str) -> str:
    s = str(cmd).strip()
    
    # Check for paths with drive letter (e.g. C:\Program Files...\something.exe)
    m = re.match(r'^[a-zA-Z]:\\([^"\r\n]*?\.(?:exe|com|bat|cmd|vbs|ps1))\b', s.strip("\"' \t"), re.IGNORECASE)
    if m:
        path = m.group(0)
        name = path.replace('\\', '/').rsplit('/', 1)[-1].lower()
        name = re.sub(r'\.(?:exe|com|bat|cmd|vbs|ps1)$', '', name)
        if name and not name.isdigit() and name not in SHELL_WRAPPERS_WIN:
            return name

    tokens = extract_executable_tokens(s, platform="windows")
    
    clean_tokens = []
    if tokens:
        for t in tokens:
            name = t.replace("\\", "/").rsplit("/", 1)[-1].lower()
            name = re.sub(r"\.(?:exe|com|bat|cmd|vbs|ps1|dll|ocx)$", "", name)
            name = re.sub(r"^(python)\d+(\.\d+)*$", r"\1", name)
            if name and not name.isdigit():
                clean_tokens.append(name)
                
    if not clean_tokens:
        # Fallback: extract first word if possible
        s_clean = re.sub(r"^\s*&\s*", "", s).strip("\"' \t")
        parts = s_clean.split(None, 1)
        if parts:
            name = parts[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
            name = re.sub(r"\.(?:exe|com|bat|cmd|vbs|ps1)$", "", name)
            name = re.sub(r"^(python)\d+(\.\d+)*$", r"\1", name)
            if name and not name.isdigit():
                clean_tokens.append(name)
                
    if not clean_tokens:
        return "z_other_system"
        
    # If the first token is a shell wrapper and a specific command is called, prefer the specific command
    specific = [t for t in clean_tokens if t not in SHELL_WRAPPERS_WIN]
    chosen = specific[0] if specific else clean_tokens[0]
    
    # Must start with a letter and have reasonable length, else group into other_system
    if not re.match(r"^[a-z][a-z0-9_\-\.]*$", chosen) or len(chosen) <= 1 or len(chosen) > 35:
        return "z_other_system"
    return chosen

def extract_tool_linux(cmd: str) -> str:
    s = str(cmd).strip()
    tokens = extract_executable_tokens(s, platform="linux")
    
    clean_tokens = []
    if tokens:
        for t in tokens:
            name = t.replace("\\", "/").rsplit("/", 1)[-1].lower()
            name = re.sub(r"\.(?:sh|py|pl|rb)$", "", name)
            name = re.sub(r"^(python)\d+(\.\d+)*$", r"\1", name)
            if name and not name.isdigit():
                clean_tokens.append(name)
                
    if not clean_tokens:
        parts = s.split(None, 1)
        if parts:
            name = parts[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
            name = re.sub(r"\.(?:sh|py|pl|rb)$", "", name)
            if name and not name.isdigit():
                clean_tokens.append(name)
                
    if not clean_tokens:
        return "z_other_system"
        
    specific = [t for t in clean_tokens if t not in SHELL_WRAPPERS_LINUX]
    chosen = specific[0] if specific else clean_tokens[0]
    
    if not re.match(r"^[a-z][a-z0-9_\-\.]*$", chosen) or len(chosen) <= 1 or len(chosen) > 35:
        return "z_other_system"
    return chosen

def export_grouped():
    # 1. Process Windows
    df_win = pd.read_csv(PROJECT_ROOT / "data" / "raw" / "windows.csv")
    df_win["tool"] = df_win["commands"].apply(extract_tool_windows)
    
    # Sort by tool alphabetically, then label (1 BAD first, then 0 GOOD), then commands
    df_win_sorted = df_win.sort_values(by=["tool", "label", "commands"], ascending=[True, False, True]).copy()
    
    # Output CSV: label,commands (1/0 at start, then comma, then command)
    df_win_out = df_win_sorted[["label", "commands"]]
    
    csv_win_out = PROJECT_ROOT / "data" / "windows_commands_grouped.csv"
    df_win_out.to_csv(csv_win_out, index=False, encoding="utf-8-sig")
    print(f"Exported Windows CSV: {csv_win_out} ({len(df_win_out)} rows, {df_win['tool'].nunique()} tool groups)")

    # 2. Process Linux
    df_linux = pd.read_csv(PROJECT_ROOT / "data" / "raw" / "linux.csv")
    df_linux["tool"] = df_linux["commands"].apply(extract_tool_linux)

    df_linux_sorted = df_linux.sort_values(by=["tool", "label", "commands"], ascending=[True, False, True]).copy()
    df_linux_out = df_linux_sorted[["label", "commands"]]

    csv_linux_out = PROJECT_ROOT / "data" / "linux_commands_grouped.csv"
    df_linux_out.to_csv(csv_linux_out, index=False, encoding="utf-8-sig")
    print(f"Exported Linux CSV: {csv_linux_out} ({len(df_linux_out)} rows, {df_linux['tool'].nunique()} tool groups)")

    # 3. Update COMMANDS_BY_TOOL.md for study and easy reference
    md_out = PROJECT_ROOT / "COMMANDS_BY_TOOL.md"
    lines = []
    lines.append("# SỔ TAY TRA CỨU CÁC LỆNH THEO TỪNG CÔNG CỤ (LOTL DETECTION)")
    lines.append("\n> **Lưu ý quan trọng về kiến trúc dữ liệu:**")
    lines.append("> File này và file `data/windows_commands_grouped.csv` được trích xuất từ dataset `data/raw/windows.csv` nhằm mục đích đọc hiểu, học tập và tra cứu.")
    lines.append("> Trong file CSV đã được sắp xếp theo từng cụm công cụ thực thi (`tool`), định dạng chuẩn: `label,commands` (1/0 ở đầu, sau dấu phẩy là câu lệnh).")
    lines.append("\n---\n")

    stats = df_win.groupby(["tool", "label"]).size().unstack(fill_value=0)
    for col in [0, 1]:
        if col not in stats.columns:
            stats[col] = 0
    stats["total"] = stats[0] + stats[1]
    stats = stats.sort_values(by="total", ascending=False)

    lines.append("## BẢNG THỐNG KÊ CÁC CÔNG CỤ NỔI BẬT\n")
    lines.append("| Công cụ (Tool) | 🔴 Số lệnh Tấn công (label=1) | 🟢 Số lệnh Lành tính (label=0) | Tổng số lệnh |")
    lines.append("| :--- | :---: | :---: | :---: |")
    for tool, row in stats.head(45).iterrows():
        if tool != "z_other_system":
            lines.append(f"| **`{tool}`** | {row[1]} | {row[0]} | {row['total']} |")
    lines.append("\n---\n")

    lines.append("## DANH SÁCH CHI TIẾT CÁC LỆNH THEO TỪNG CÔNG CỤ\n")
    top_focus_tools = [
        "msbuild", "wmic", "certutil", "powershell", "rundll32", "mshta",
        "cscript", "regsvr32", "reg", "cmd", "netsh", "net", "schtasks",
        "sc", "at", "bitsadmin", "curl", "tar", "python", "git", "update"
    ]
    all_grouped_tools = sorted([t for t in df_win["tool"].unique() if t != "z_other_system"])
    ordered_tools = [t for t in top_focus_tools if t in all_grouped_tools] + [t for t in all_grouped_tools if t not in top_focus_tools]

    for tool in ordered_tools:
        sub = df_win[df_win["tool"] == tool]
        bad_cmds = sub[sub["label"] == 1]["commands"].unique()
        good_cmds = sub[sub["label"] == 0]["commands"].unique()

        lines.append(f"### 📦 Công cụ: `{tool}` (Tổng: {len(sub)} lệnh)")
        lines.append(f"- 🔴 **Tấn công (label=1):** {len(bad_cmds)} lệnh")
        lines.append(f"- 🟢 **Lành tính (label=0):** {len(good_cmds)} lệnh\n")

        if len(bad_cmds) > 0:
            lines.append("#### 🔴 Các lệnh Tấn công (label=1):")
            lines.append("```bat")
            for c in bad_cmds:
                lines.append(c)
            lines.append("```\n")

        if len(good_cmds) > 0:
            lines.append("#### 🟢 Các lệnh Lành tính (label=0):")
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
