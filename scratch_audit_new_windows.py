import pandas as pd
import re
from difflib import SequenceMatcher

path = r'D:\Github\LotLDetection\data\raw\windows.csv'
df = pd.read_csv(path)
cmd_col = 'commands'
label_col = 'label'

print(f"=== COMPREHENSIVE AUDIT REPORT FOR {path} ===")
print(f"Total Rows: {len(df)}")
print(f"Columns: {df.columns.tolist()}")
print(f"Label Counts:\n{df[label_col].value_counts().to_string()}\n")

# 1. EXACT DUPLICATES & CONFLICTS
exact_groups = df.groupby(cmd_col)[label_col].unique()
exact_conflicts = exact_groups[exact_groups.apply(len) > 1]
print(f"1. EXACT LABEL CONFLICTS: {len(exact_conflicts)}")
for c in exact_conflicts.index:
    print("  [EXACT CONFLICT]:", repr(c), "-> labels:", df[df[cmd_col]==c][label_col].tolist())

# Exact duplicate rows (same cmd, same label)
dup_exact_rows = df.duplicated(subset=[cmd_col, label_col], keep=False)
print(f"   Duplicate rows (same cmd, same label): {dup_exact_rows.sum()}")

# 2. NORMALIZED CONFLICTS (case + whitespace)
def norm(s):
    if not isinstance(s, str): return ''
    s = s.strip()
    s = re.sub(r'\s+', ' ', s)
    return s.lower()

df['norm_cmd'] = df[cmd_col].apply(norm)
norm_groups = df.groupby('norm_cmd')[label_col].unique()
norm_conflicts = norm_groups[norm_groups.apply(len) > 1]
print(f"\n2. NORMALIZED LABEL CONFLICTS: {len(norm_conflicts)}")
for c in norm_conflicts.index:
    sub = df[df['norm_cmd']==c]
    print("  [NORM CONFLICT]:", repr(c))
    for _, r in sub.iterrows():
        print(f"     Label {r[label_col]}: {repr(r[cmd_col])}")

# 3. PLACEHOLDER AUDIT
patterns = [
    r'\{[A-Z0-9_:]+\}',
    r'<[A-Za-z0-9_]+>',
    r'\binputfilename\b',
    r'\boutputfilename\b',
    r'\bencodedinputfilename\b',
    r'\bcalc\.exe\b',
    r'\bevil\.exe\b',
    r'\bpayload\.exe\b',
    r'\bpayload\.dll\b'
]
comb_pattern = '|'.join(patterns)
ph_matches = df[df[cmd_col].str.contains(comb_pattern, case=False, regex=True, na=False)]
print(f"\n3. PLACEHOLDER / SYNTHETIC PHRASES AUDIT:")
print(f"   Total rows with potential placeholders/synthetic tokens: {len(ph_matches)}")
if len(ph_matches) > 0:
    print("   Sample placeholder rows:")
    for _, r in ph_matches.head(15).iterrows():
        print(f"     [Label {r[label_col]}] {repr(r[cmd_col])}")

# 4. NON-LOLBIN BACKGROUND NOISE TOOLS
noise_tools = {'conhost.exe', 'conhost', 'onedrivestandaloneupdater.exe', 'onedrivestandaloneupdater',
               'git.exe', 'git', 'code.exe', 'code', 'msedge.exe', 'msedge', 'msedgewebview2.exe',
               'msedgewebview2', 'python.exe', 'python', 'python3.11.exe', 'python3.11', 'python3.exe',
               'update.exe', 'update', 'tasklist.exe', 'tasklist', 'arp.exe', 'arp', '7z.exe', '7z',
               'dllhost.exe', 'dllhost', 'wevtutil.exe', 'wevtutil', 'openconsole.exe', 'openconsole',
               'teams.exe', 'teams', 'explorer.exe', 'explorer', 'outlook.exe', 'outlook', 'excel.exe', 'excel',
               'winword.exe', 'winword', 'svchost.exe', 'svchost', 'systeminfo.exe', 'whoami.exe', 'ipconfig.exe',
               'notepad.exe'}

def get_tool(cmd):
    if not isinstance(cmd, str): return 'unknown'
    tokens = re.findall(r'[a-zA-Z0-9_\-\.]+', cmd.lower())
    for t in tokens:
        clean = t.split('\\')[-1].split('/')[-1]
        if clean.endswith('.exe') or clean.endswith('.dll') or clean.endswith('.vbs'):
            return clean
        if clean in ['certutil', 'powershell', 'wmic', 'bitsadmin', 'mshta', 'rundll32', 'regsvr32',
                     'cscript', 'wscript', 'cmd', 'reg', 'schtasks', 'net', 'net1', 'sc', 'tasklist',
                     'certreq', 'installutil', 'msbuild', 'regasm', 'regsvcs', 'cmstp', 'forfiles',
                     'psexec', 'procdump', 'at', 'atbroker', 'bash', 'conhost', 'curl', 'msiexec',
                     'hh', 'expand', 'extrac32', 'makecab', 'diantz', 'esentutl', 'cipher', 'fsutil',
                     'findstr', 'mpcmdrun', 'winget', 'wuauclt', 'odbcconf', 'pcalua', 'verclsid',
                     'dotnet', 'openconsole', 'createdump', 'sqlps', 'wsl', 'cmdkey', 'msxsl', 'xwizard', 'squirrel']:
            return clean
    return tokens[0] if tokens else 'unknown'

df['tool'] = df[cmd_col].apply(get_tool)
noise_rows = df[df['tool'].isin(noise_tools)]
print(f"\n4. NON-LOLBIN BACKGROUND NOISE AUDIT:")
print(f"   Total background noise rows found: {len(noise_rows)}")
if len(noise_rows) > 0:
    print("   Breakdown of noise rows by tool:")
    print(noise_rows.groupby('tool')[label_col].value_counts().to_string())

# 5. TOOL-BY-TOOL DISTRIBUTION
print(f"\n5. TOP 30 TOOLS DISTRIBUTION IN DATASET:")
tool_stats = df.groupby('tool').agg(
    total=(label_col, 'count'),
    benign=(label_col, lambda x: (x==0).sum()),
    malicious=(label_col, lambda x: (x==1).sum())
).sort_values(by='total', ascending=False)
print(tool_stats.head(30).to_string())

# 6. NEAR-DUPLICATE CONFLICTING PAIRS
def tokenize(s):
    return set(re.findall(r'[a-zA-Z0-9_\-]+', s.lower()))

def jaccard(s1, s2):
    t1, t2 = tokenize(s1), tokenize(s2)
    if not t1 or not t2: return 0.0
    return len(t1 & t2) / len(t1 | t2)

dual_tools = tool_stats[(tool_stats['benign'] > 0) & (tool_stats['malicious'] > 0)].index.tolist()
high_sim_pairs = []
for t in dual_tools:
    cmds0 = df[(df['tool'] == t) & (df[label_col] == 0)][cmd_col].unique()
    cmds1 = df[(df['tool'] == t) & (df[label_col] == 1)][cmd_col].unique()
    for c0 in cmds0:
        for c1 in cmds1:
            j_sim = jaccard(c0, c1)
            s_sim = SequenceMatcher(None, c0.lower(), c1.lower()).ratio()
            if j_sim >= 0.75 or s_sim >= 0.85:
                high_sim_pairs.append({
                    'tool': t,
                    'jaccard': round(j_sim, 2),
                    'ratio': round(s_sim, 2),
                    'c0': c0,
                    'c1': c1
                })

print(f"\n6. NEAR-DUPLICATE CONFLICTING PAIRS (Sim >= 0.8): {len(high_sim_pairs)}")
for p in high_sim_pairs[:10]:
    print(f"  Tool: {p['tool']} | Jaccard: {p['jaccard']} | Ratio: {p['ratio']}")
    print(f"    [0-Benign]   : {repr(p['c0'])}")
    print(f"    [1-Malicious]: {repr(p['c1'])}")
