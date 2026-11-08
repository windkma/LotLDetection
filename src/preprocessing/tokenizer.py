"""
Command line tokenizer for Windows CMD and Linux POSIX shells.
"""

import re
import shlex

_RE_WIN_CMD = re.compile(
    r'"((?:""|\\[\"\\]|[^"])*)?"?()|(\\\\(?=\\*")|\\")|(&&?|\|\|?|\d?>|[<])'
    r'|([^\s"&|<>]+)|(\s+)|(.)'
)


def _split_once_windows(s: str) -> list:
    args = []
    accu = None
    for qs, qss, esc, pipe, word, white, fail in _RE_WIN_CMD.findall(s):
        if word:
            pass
        elif esc:
            word = esc[1]
        elif white or pipe:
            if accu is not None:
                args.append(accu)
            if pipe:
                args.append(pipe)
            accu = None
            continue
        elif fail:
            continue
        elif qs:
            word = qs.replace('\\"', '"').replace('\\\\', '\\').replace('""', '"')
        else:
            word = qss

        accu = (accu or '') + word

    if accu is not None:
        args.append(accu)

    return args


def split_windows(command: str) -> list:
    """
    Tokenize Windows command lines with iterative quote resolution.
    """
    s = command.strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]

    current = [s]
    while True:
        expanded = []
        for tok in current:
            if tok.startswith('"') and tok.endswith('"'):
                tok = tok[1:-1]
            parts = _split_once_windows(tok)
            expanded.extend(parts)
        if expanded == current:
            break
        current = expanded

    return current


def split_linux(command: str) -> list:
    """
    Tokenize Linux POSIX command lines using iterative shlex parsing.
    """
    def _split_once(s: str) -> list:
        try:
            lex = shlex.shlex(s, punctuation_chars=True, posix=True)
            lex.whitespace_split = False
            return list(lex)
        except ValueError:
            return [s]

    current = [command]
    while True:
        expanded = []
        for tok in current:
            parts = _split_once(tok)
            expanded.extend(parts)
        if expanded == current:
            break
        current = expanded

    return current


def extract_executable_tokens(command: str, platform: str = "windows") -> list:
    """Extract only tokens that occupy an execution position in the command line.

    Recognizes:
    - Initial command position.
    - Executables following chaining operators (&, &&, |, ||, ;, newline).
    - Executables following shell wrappers (cmd /c, powershell -c, sudo, nohup, etc.).
    - Executables spawned via execution verbs (create, start, runas).
    """
    if platform == "windows":
        raw_tokens = split_windows(command)
        delimiters = {'&', '&&', '|', '||', ';'}
        shell_binaries = {'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe', 'wsl', 'wsl.exe', 'bash', 'bash.exe'}
        wrapper_flags = {'/c', '/k', '-c', '-command', '-encodedcommand', '-enc', '/tr', '/run'}
        wrapper_commands = {'sudo', 'runas', 'create', 'start'}
    else:
        raw_tokens = split_linux(command)
        delimiters = {';', '&', '&&', '|', '||', '\n'}
        shell_binaries = {'sh', 'bash', 'dash', 'zsh', 'ksh'}
        wrapper_flags = {'-exec', '-ok'}
        wrapper_commands = {'sudo', 'doas', 'su', 'nohup', 'nice', 'xargs', 'eval', 'exec', 'chroot'}

    exec_tokens = []
    next_is_exec = True
    last_exec_bin = ''

    for i, tok in enumerate(raw_tokens):
        clean = tok.strip('"\' \t')
        if not clean:
            continue

        if next_is_exec:
            if platform == "windows" and clean.lower() == 'set' and i + 1 < len(raw_tokens) and '=' in raw_tokens[i + 1]:
                next_is_exec = False
                continue
            base_name = clean.replace('\\', '/').rsplit('/', 1)[-1]
            exec_tokens.append(base_name)
            last_exec_bin = base_name.lower().split('.')[0]
            next_is_exec = (clean.lower() in wrapper_commands or base_name.lower() in wrapper_commands)
            continue

        if clean in delimiters:
            next_is_exec = True
            continue

        if clean.lower() in wrapper_flags:
            next_is_exec = True
            continue

        if last_exec_bin in shell_binaries and clean.lower() in {'-c', '/c', '/k', '-command'}:
            next_is_exec = True
            continue

        if clean.lower() in wrapper_commands:
            next_is_exec = True
            continue

    return exec_tokens
