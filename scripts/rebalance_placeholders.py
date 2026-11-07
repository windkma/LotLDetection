"""Rebalance and instantiate LOLBAS placeholder commands in data/raw/windows.csv.

Applies the 40% Normal / 40% Sensitive Local / 20% Network path distribution.
"""
import re
import shutil
from pathlib import Path
import pandas as pd

CSV_PATH = Path('data/raw/windows.csv')
BACKUP_PATH = Path('data/raw/windows.csv.bak_before_rebalance')

# Create backup
shutil.copy2(CSV_PATH, BACKUP_PATH)
print(f'Backup saved to {BACKUP_PATH}')

class BalancedPathDistributor:
    def __init__(self):
        self.idx = 0
        # 40% Normal/Relative bases
        self.normal_bases = [
            'payload', 'script', 'test', 'build', 'job', 'data',
            r'C:\Projects\payload', r'C:\Tools\script', r'C:\Builds\job', r'C:\Dev\test'
        ]
        # 40% Sensitive Local bases
        self.sensitive_bases = [
            r'C:\Windows\Temp\payload', r'C:\Windows\Temp\test',
            r'C:\Users\Public\script', r'C:\Users\Public\Downloads\payload',
            r'C:\ProgramData\test', r'C:\Windows\System32\Tasks\job',
            r'C:\Users\Public\Libraries\build', r'C:\Windows\Temp\evil'
        ]
        # 20% Network / UNC bases
        self.network_bases = [
            r'\\10.10.10.10\share\payload', r'\\10.10.10.10\public\script',
            r'\\fileserver\c$\test', r'\\192.168.1.50\share\job',
            r'\\172.16.0.5\share\data'
        ]
        self.urls = [
            'http://10.10.10.10/payload',
            'http://evil.com/script',
            'https://raw.githubusercontent.com/attacker/repo/main/run',
            'http://192.168.1.100:8080/test',
            'http://attacker.com/build',
            'https://gist.githubusercontent.com/attacker/test/raw/job'
        ]
        self.cmds = [
            'calc.exe', 'whoami', 'cmd.exe /c calc.exe', 'notepad.exe',
            'powershell.exe -ep bypass -c calc.exe'
        ]

    def get_path(self, ext='', is_absolute=False, is_smb=False):
        self.idx += 1
        slot = self.idx % 10
        if is_smb or slot in (8, 9):
            base = self.network_bases[self.idx % len(self.network_bases)]
            return f"{base}_{self.idx}{ext}" if ext else f"{base}_{self.idx}"
        elif slot in (4, 5, 6, 7) or (is_absolute and slot in (2, 3)):
            base = self.sensitive_bases[self.idx % len(self.sensitive_bases)]
            return f"{base}_{self.idx}{ext}" if ext else f"{base}_{self.idx}"
        else:
            if is_absolute:
                base = r"C:\Projects\payload"
            else:
                base = self.normal_bases[self.idx % len(self.normal_bases)]
            return f"{base}_{self.idx}{ext}" if ext else f"{base}_{self.idx}"

    def get_url(self, ext=''):
        self.idx += 1
        base = self.urls[self.idx % len(self.urls)]
        return f"{base}_{self.idx}{ext}" if ext else f"{base}_{self.idx}"

    def get_cmd(self):
        self.idx += 1
        return self.cmds[self.idx % len(self.cmds)]

dist = BalancedPathDistributor()

def replace_command_placeholders(cmd: str) -> str:
    # 1. PATH_SMB
    def sub_smb(m):
        full = m.group(0)
        ext = ''
        if ':' in full:
            part = full.split(':', 1)[1].rstrip('}')
            if part.startswith('.'):
                ext = part
            elif part == 'folder':
                return r'\\10.10.10.10\share'
        return dist.get_path(ext, is_smb=True)

    cmd = re.sub(r'\{PATH_SMB(?::[^\}]+)?\}', sub_smb, cmd)

    # 2. REMOTEURL
    def sub_url(m):
        full = m.group(0)
        ext = ''
        if ':' in full:
            part = full.split(':', 1)[1].rstrip('}')
            if part.startswith('.'):
                ext = part
        return dist.get_url(ext)

    cmd = re.sub(r'\{REMOTEURL(?::[^\}]+)?\}', sub_url, cmd)

    # 3. PATH_ABSOLUTE
    def sub_abs(m):
        full = m.group(0)
        ext = ''
        if ':' in full:
            part = full.split(':', 1)[1].rstrip('}')
            if part.startswith('.'):
                ext = part
            elif part == 'folder':
                return r'C:\Users\Public\Downloads' if (dist.idx % 2 == 0) else r'C:\Projects\Build'
        return dist.get_path(ext, is_absolute=True)

    cmd = re.sub(r'\{PATH_ABSOLUTE(?::[^\}]+)?\}', sub_abs, cmd)

    # 4. PATH
    def sub_path(m):
        full = m.group(0)
        ext = ''
        if ':' in full:
            part = full.split(':', 1)[1].rstrip('}')
            if part.startswith('.'):
                ext = part
        return dist.get_path(ext, is_absolute=False)

    cmd = re.sub(r'\{PATH(?::[^\}]+)?\}', sub_path, cmd)

    # 5. CMD
    def sub_cmd(m):
        return dist.get_cmd()
    cmd = re.sub(r'\{CMD(?::args)?\}', sub_cmd, cmd)

    # 6. Specific identifiers
    cmd = re.sub(r'\{CLSID\}', '{00021401-0000-0000-C000-000000000046}', cmd)
    cmd = re.sub(r'\{GUID\}', '{7FC3863B-7471-4B10-84E3-A5C2E0330618}', cmd)
    cmd = re.sub(r'\{MY_MSI_GUID\}', '{23960514-F0B6-4854-A820-245EB0232C14}', cmd)
    cmd = re.sub(r'\{ExistingServiceName\}', 'Spooler', cmd)
    cmd = re.sub(r'\{process_name\}', 'notepad.exe', cmd)
    cmd = re.sub(r'\{PID\}', '1234', cmd)
    cmd = re.sub(r'\{LSASS_PID\}', '672', cmd)
    cmd = re.sub(r'\{HOST\}', '10.10.10.10', cmd)
    cmd = re.sub(r'\{PORT\}', '8080', cmd)
    cmd = re.sub(r'\{LENGTH_IN_BYTES\}', '1024', cmd)
    cmd = re.sub(r'\{bootloadersettings\}', 'boot', cmd)
    cmd = re.sub(r'\{current\}', 'boot', cmd)
    cmd = re.sub(r'\{boot\|hibernate\|standby\|shutdown\|rebootCycle\}', 'boot', cmd)
    cmd = re.sub(r'\{cef_version\}', '100', cmd)
    cmd = re.sub(r'\{your-base64-data\}', 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAA', cmd)

    return cmd

def main():
    df = pd.read_csv(CSV_PATH)
    pattern = r'\{(?:PATH|PATH_ABSOLUTE|PATH_SMB|REMOTEURL|CMD|CLSID|GUID|ExistingServiceName|process_name|PID)(?::[^\}]+)?\}'
    mask = df['commands'].str.contains(pattern, regex=True, na=False)
    print(f'Total commands: {len(df)}, placeholder commands to replace: {mask.sum()}')

    updated_cmds = []
    replaced_count = 0
    for cmd in df['commands']:
        if re.search(pattern, str(cmd)):
            new_cmd = replace_command_placeholders(str(cmd))
            updated_cmds.append(new_cmd)
            replaced_count += 1
        else:
            updated_cmds.append(cmd)

    df['commands'] = updated_cmds

    # Check remaining placeholders
    remaining = df['commands'].str.contains(pattern, regex=True, na=False).sum()
    print(f'Remaining placeholders: {remaining}')

    # Check duplicates
    dups = df['commands'].duplicated().sum()
    print(f'Duplicate commands in updated dataset: {dups}')

    # Save
    df.to_csv(CSV_PATH, index=False)
    print(f'Successfully updated {CSV_PATH} with {replaced_count} replaced commands!')

if __name__ == '__main__':
    main()
