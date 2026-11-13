"""
Command line normalizer and deobfuscation utilities.
"""

import re
import base64
import binascii
import ntpath
from ipaddress import ip_address

_RE_IPV4 = re.compile(
    r"(?<![\w.])(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}(?![\w.])"
)
# Match the complete hostname in URLs, UNC paths and host arguments.
# Exclude domains/file names such as localhost.example.com and localhost.txt.
_RE_LOCALHOST = re.compile(r"(?<![\w.-])localhost(?![\w.-])", re.IGNORECASE)
_COMMAND_TOKEN = re.compile(r'"[^"\r\n]*"|[^\s]+')
_POWERSHELL_NAMES = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_CMD_NAMES = {"cmd", "cmd.exe"}
_PS_CONTROL_ESCAPES = set("0abefnrtuv")
MAX_ANALYSIS_VIEWS = 8
MAX_ENCODED_LENGTH = 16384


def deobfuscate_cmd(command: str) -> str:
    """Join simple CMD identifier escapes; preserve quoted data and operators.

    This is a detection view, not a complete cmd.exe interpreter. In particular,
    do not turn ^&, ^| or ^^ into shell syntax, or expand environment variables.
    """
    result = []
    quoted = False
    first_token = re.match(r"\s*\S+", command)
    program_end = first_token.end() if first_token else 0
    index = 0
    while index < len(command):
        character = command[index]
        following = command[index + 1:index + 2]
        if character == "^" and not quoted:
            if following == "^":
                result.append("^^")
                index += 2
                continue
            if following and following.isascii() and (following.isalnum() or following in "_./\\:-"):
                index += 1
                continue
            if following in {"\r", "\n"}:
                index += 2
                if following == "\r" and command[index:index + 1] == "\n":
                    index += 1
                continue
            if following:
                result.append(character + following)
                index += 2
                continue
        if character == '"':
            # Only remove empty quote fragments embedded in a bare identifier.
            previous = command[index - 1:index] if index else ""
            after_pair = command[index + 2:index + 3]
            if not quoted and index < program_end and following == '"' and previous.isalnum() and after_pair.isalnum():
                index += 2
                continue
            quoted = not quoted
        result.append(character)
        index += 1
    return "".join(result)


def _deobfuscate_powershell(command):
    """Remove non-special backtick escapes outside string literals only."""
    result = []
    quote = None
    index = 0
    while index < len(command):
        character = command[index]
        following = command[index + 1:index + 2]
        if quote:
            if character == "`" and quote == '"' and following:
                result.append(character + following)
                index += 2
                continue
            if character == quote:
                if following == quote:
                    result.append(character + following)
                    index += 2
                    continue
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character == "`" and following:
            if following in {"\r", "\n"}:
                index += 2
                if following == "\r" and command[index:index + 1] == "\n":
                    index += 1
                continue
            if following.isascii() and (following.isalnum() or following == "_") and following not in _PS_CONTROL_ESCAPES:
                index += 1
                continue
            result.append(character + following)
            index += 2
            continue
        result.append(character)
        index += 1
    return "".join(result)


def _unwrap_argument(text, allow_single=False):
    text = text.strip()
    quotes = {"'", '"'} if allow_single else {'"'}
    if len(text) >= 2 and text[0] == text[-1] and text[0] in quotes:
        return text[1:-1]
    return text


def _shell_payload(command, shell):
    """Read explicit shell options, stopping at -Command or -File boundaries."""
    tokens = list(_COMMAND_TOKEN.finditer(command))
    if not tokens:
        return None
    if shell == "powershell" and tokens[0].group().startswith(("'", '"')):
        # A quoted expression is data unless a call operator invokes it.
        return None
    program = ntpath.basename(_unwrap_argument(deobfuscate_cmd(tokens[0].group()))).lower()
    if program not in _POWERSHELL_NAMES | _CMD_NAMES:
        return None
    for position, token in enumerate(tokens[1:], start=1):
        option = token.group().lower()
        if program in _CMD_NAMES:
            if option in {"/c", "/k"}:
                return "cmd", _unwrap_argument(command[token.end():], allow_single=shell == "powershell")
            continue
        if option in {"-file", "-f", "--%"}:
            return None
        if option in {"-command", "-c"}:
            return "powershell", _unwrap_argument(command[token.end():], allow_single=shell == "powershell")
        if option in {"-encodedcommand", "-enc", "-ec", "-e"}:
            if position + 1 >= len(tokens):
                return None
            encoded = _unwrap_argument(tokens[position + 1].group(), allow_single=shell == "powershell")
            if len(encoded) > MAX_ENCODED_LENGTH:
                return None
            try:
                decoded = base64.b64decode(encoded, validate=True).decode("utf-16-le").lstrip("\ufeff")
            except (binascii.Error, UnicodeError, ValueError):
                return None
            if not decoded or any(not char.isprintable() and char not in "\r\n\t" for char in decoded):
                return None
            return "powershell", decoded
    return None


def windows_analysis_views(command):
    """Keep original text and at most eight bounded shell-aware analysis views.

    Payloads are decoded as text only. Never call a shell, expand variables,
    resolve wildcards or evaluate PowerShell expressions.
    """
    pending = [(str(command), "cmd", 0)]
    visited = set()
    views = []
    while pending and len(views) < MAX_ANALYSIS_VIEWS:
        text, shell, depth = pending.pop(0)
        if (text, shell) in visited:
            continue
        visited.add((text, shell))
        if text not in views:
            views.append(text)
        if depth >= 3:
            continue
        tokens = list(_COMMAND_TOKEN.finditer(text))
        program = ntpath.basename(_unwrap_argument(deobfuscate_cmd(tokens[0].group()))).lower() if tokens else ""
        if program in _POWERSHELL_NAMES:
            # The caller's CMD escape rules must not alter a PowerShell script.
            normalized = text
        else:
            normalized = _deobfuscate_powershell(text) if shell == "powershell" else deobfuscate_cmd(text)
        if normalized != text:
            pending.append((normalized, shell, depth + 1))
        payload = _shell_payload(normalized, shell)
        if payload and payload[1]:
            pending.append((payload[1], payload[0], depth + 1))
    return tuple(views)


def extract_ip_labels(command: str) -> list:
    """
    Recognize the localhost hostname and classify IPv4 addresses:
    IP_LOOPBACK, IP_PRIVATE, IP_LINK_LOCAL, IP_MULTICAST, IP_RESERVED,
    IP_PUBLIC, IP_UNSPECIFIED.
    """
    labels = {}
    if _RE_LOCALHOST.search(str(command)):
        labels['IP_LOOPBACK'] = 0
    try:
        matches = _RE_IPV4.finditer(f" {command} ")
        for match in matches:
            try:
                clean_ip = "".join(ch for ch in match.group(0) if ch.isalnum() or ch == ".")
                ipt = ip_address(clean_ip)
                if ipt.is_link_local:
                    resp = "link_local"
                elif ipt.is_loopback:
                    resp = "loopback"
                elif ipt.is_multicast:
                    resp = "multicast"
                elif ipt.is_reserved:
                    resp = "reserved"
                elif ipt.is_unspecified:
                    resp = "unspecified"
                elif ipt.is_private:
                    resp = "private"
                elif ipt.is_global:
                    resp = "public"
                else:
                    resp = "public"

                label = f"IP_{resp.upper()}"
                labels[label] = 0
            except ValueError:
                continue
    except Exception:
        pass

    return list(labels.keys())
