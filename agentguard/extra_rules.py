"""Additional native static rules (AG005-AG011).

These rules never execute skill content. They look for the behaviours that the
public malicious-skill corpora use to evade simple credential/network
matching:

* AG005 environment harvesting (``os.environ.items()``, ``env | base64``)
* AG006 hidden content (payload after a wall of blank lines, invisible Unicode)
* AG007 suspicious artifacts (``.pyc`` bytecode, archives disguised as text)
* AG008 supply-chain redirection (registry overrides, ``curl | sh``)
* AG009 prompt injection in skill documentation
* AG010 decode-and-execute chains and dynamic ``compile()`` of non-literal source
* AG011 direct access to system secret files (``/etc/shadow``, service-account tokens)

Every rule returns the normalized :class:`agentguard.models.Finding` schema.
"""
from __future__ import annotations

import io
import re
import urllib.parse
import zipfile
from pathlib import Path

from .custom_rules import _NETWORK, _finding
from .models import Finding

_CODE_SUFFIXES = {".py", ".sh", ".bash", ".js", ".mjs", ".ts", ".rb", ".pl", ".ps1", ".bat", ".cmd"}
_DOC_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ""}
_MAX_TEXT_BYTES = 2 * 1024 * 1024
_SKIP_DIRS = {".git", "node_modules"}
_IGNORED_NAMES = {"_expected.json"}  # answer-key files shipped with public eval corpora

# --------------------------------------------------------------------------- AG005
_ENV_HARVEST = re.compile(
    r"(?:os\.environ\.(?:items|copy|values|keys)\s*\(|dict\s*\(\s*os\.environ\s*\)|"
    r"\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+os\.environ\b|"
    r"json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ|os\.environb|"
    r"\bprintenv\b|(?<![\w.\-/])env\s*\|\s*\w|\bexport\s+-p\b|"
    r"Object\.(?:entries|keys|assign)\s*\([^)]*process\.env|\.\.\.\s*process\.env|"
    r"JSON\.stringify\s*\(\s*process\.env)"
)

# --------------------------------------------------------------------------- AG006
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\U000e0000-\U000e007f]")
_ESCAPED_TAG = re.compile(r"\\U000[Ee]00[0-7][0-9A-Fa-f]|\\[ux]\{[Ee]00[0-7][0-9A-Fa-f]\}")
_BLANK_RUN = 30
_PAD_RUN = 120

# --------------------------------------------------------------------------- AG007
_ARCHIVE_SUFFIXES = {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".jar", ".whl", ".apk", ".epub", ".nupkg"}
_SCRIPT_ENTRY = re.compile(r"\.(?:sh|bash|py|ps1|bat|cmd|exe|dll|js|vbs|vbaProject\.bin)$", re.I)
_SUSPICIOUS_PYC_NAMES = (
    "environ", "getenv", "urlopen", "socket", "subprocess", "system", "popen",
    "b64decode", "exec", "eval", "requests", "urllib", "http", "connect", "sendall",
)

# --------------------------------------------------------------------------- AG008
_OFFICIAL_REGISTRY_HOSTS = {
    "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
    "pypi.python.org", "upload.pypi.org", "test.pypi.org", "rubygems.org", "crates.io",
    "index.crates.io", "proxy.golang.org", "npmjs.com", "www.npmjs.com", "www.npmjs.org",
}
_SUSPICIOUS_TLDS = (".invalid", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", ".mov", ".onion")
_REGISTRY_LINE = re.compile(r"registry|index[-_]url|extra[-_]index|\.npmrc|\.yarnrc|pip\.conf", re.I)
_URL = re.compile(r"https?://([A-Za-z0-9.\-]+)(?::\d+)?[^\s\"'<>)]*")
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+(?:-\w+\s+)?)?(?:ba|z|da|k)?sh\b", re.I,
)
_DIRECT_URL_INSTALL = re.compile(
    r"(?:\b(?:npm|yarn|pnpm)\s+(?:install|i|add)\b[^\n]*https?://|"
    r"\bpip3?\s+install\b[^\n]*(?:https?://|git\+))", re.I,
)

# --------------------------------------------------------------------------- AG009
_INJECTION = re.compile(
    r"(?:ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|directions)|"
    r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above)|"
    r"do\s+not\s+(?:mention|tell|reveal|disclose|inform)\s+(?:(?:this|that|it|these|about|any(?:thing)?)\b[^.\n]{0,60}\buser|"
    r"the\s+user\s+(?:about|that|of|what))|"
    r"without\s+(?:telling|informing|notifying)\s+the\s+user|"
    r"(?:hide|conceal|cover\s+up)\s+(?:this|that|these|the)\s+(?:action|step|command|operation|activity|change)s?\b|"
    r"(?:hide|conceal)\b[^.\n]{0,40}\bfrom\s+the\s+user|"
    r"silently\s+(?:run|execute|read|send|upload|cat|curl)|"
    r"(?:reveal|print|show|output)\s+(?:your\s+|the\s+)?system\s+prompt|"
    r"you\s+are\s+now\s+in\s+(?:developer|debug|admin|unrestricted|god)\s+mode|"
    r"system\s+note\s+for\s+the\s+assistant|"
    r"override\s+(?:your\s+)?safety)", re.I,
)
_DEFENSIVE = re.compile(
    r"\b(?:never|don'?t|do\s+not|must\s+not|should\s+not|avoid|refuse|reject|beware|hostile|"
    r"treat\s+as\s+(?:data|untrusted)|is\s+a\s+sign\s+of|sign\s+of\s+a)\b", re.I,
)


def _defensive(text: str, start: int, end: int | None = None, *, whole_line: bool = False) -> bool:
    """True when the match sits in a sentence that warns *against* the behaviour.

    Public skills (for example ``anthropics/skills``) document these patterns as things to refuse.
    Such hits are kept but downgraded to LOW instead of being reported as attacks.
    """
    line_start = text.rfind("\n", 0, start) + 1
    if whole_line:
        line_end = text.find("\n", end if end is not None else start)
        window = text[line_start: line_end if line_end != -1 else len(text)]
    else:
        window = text[max(line_start, start - 160):start]
    return bool(_DEFENSIVE.search(window))


_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_COMMENT_INSTRUCTION = re.compile(
    r"(?:assistant|agent|claude|system|ignore|silently|\bcat\b|curl|\.ssh|credential|exfiltrat|base64|"
    r"do not (?:mention|tell))", re.I,
)
_SENSITIVE_PATH = re.compile(r"(?:\.ssh|\.aws|\.git-credentials|\.netrc|id_rsa|id_ed25519|/etc/shadow|\.env\b)", re.I)

# --------------------------------------------------------------------------- AG011
_SYSTEM_SECRET = re.compile(
    r"(?:/etc/(?:shadow|gshadow|sudoers)\b|/proc/(?:\d+|self)/environ|"
    r"/var/run/secrets/kubernetes\.io|/run/secrets/kubernetes\.io|/root/\.ssh)"
)

# --------------------------------------------------------------------------- AG010
_DYNAMIC_COMPILE = re.compile(r"\bcompile\s*\(\s*[A-Za-z_]\w*\s*,[^)\n]*[\"'](?:exec|eval)[\"']")
_DECODER_NAMES = {
    "b64decode", "urlsafe_b64decode", "a85decode", "b85decode", "unhexlify", "fromhex",
    "decompress", "loads", "rot13", "b32decode",
}
_ALIAS_IMPORT = re.compile(r"from\s+[\w.]+\s+import\s+([^\n]+)")
_ALIAS_ASSIGN = re.compile(r"^[ \t]*(\w+)[ \t]*=[ \t]*(?:[\w.]+\.)?(?P<decoder>%s)[ \t]*$" % "|".join(sorted(_DECODER_NAMES)), re.M)
_REMOTE_EXEC = re.compile(r"\b(?:exec|eval)\s*\([^)\n]*(?:urlopen|requests\.get|\.read\s*\(\))", re.I)
_SHELL_DECODE_EXEC = re.compile(
    r"(?:base64\s+(?:-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", re.I,
)
_JS_DECODE_EXEC = re.compile(r"\b(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(", re.I)


def _is_text(data: bytes) -> bool:
    return b"\x00" not in data[:4096]


def _files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts) or path.name in _IGNORED_NAMES:
            continue
        yield path


def _text_files(root: Path):
    for path in _files(root):
        try:
            if path.stat().st_size > _MAX_TEXT_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if not _is_text(data):
            continue
        yield path, data.decode("utf-8", errors="replace")


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _snippet(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip()[:500] if 0 < line <= len(lines) else ""


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


# =========================================================================== AG005
_ENV_FILTER_OUT = re.compile(r"\bif\s+\w+\s*(?:!=|\bnot\s+in\b)")


def _benign_env_use(text: str, match: re.Match[str]) -> bool:
    """Copying the environment for a child process, or removing a key from it, is not harvesting."""
    indicator = match.group(0)
    if indicator.startswith("os.environ.copy"):
        return True
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.end())
    line = text[line_start: line_end if line_end != -1 else len(text)]
    if _ENV_FILTER_OUT.search(line) and ("{" in line or "dict(" in line or "[" in line):
        return True  # {k: v for k, v in os.environ.items() if k != "X"}
    return False


def env_harvest(root: Path) -> list[Finding]:
    results = []
    for path, text in _text_files(root):
        match = next((m for m in _ENV_HARVEST.finditer(text) if not _benign_env_use(text, m)), None)
        if not match:
            continue
        sink = _NETWORK.search(text) or re.search(r"\b(?:curl|wget|nc)\b", text)
        severity = "HIGH" if sink else "MEDIUM"
        line = _line_of(text, match.start())
        results.append(_finding(
            "AG005", "env_harvest", severity,
            "Bulk environment-variable access (credential harvesting pattern)",
            _rel(path, root), line, _snippet(text, line),
            {"indicator": match.group(0)[:200], "network_sink_in_file": bool(sink)},
            "Read only the specific variables the skill needs; never dump or forward the whole environment.",
        ))
    return results


# =========================================================================== AG006
def hidden_content(root: Path) -> list[Finding]:
    results = []
    for path, text in _text_files(root):
        relative = _rel(path, root)
        severity = "HIGH" if path.suffix.lower() in _CODE_SUFFIXES else "MEDIUM"
        lines = text.split("\n")
        blank = 0
        reported = False
        for index, line in enumerate(lines):
            if not line.strip():
                blank += 1
                continue
            if blank >= _BLANK_RUN:
                results.append(_finding(
                    "AG006", "hidden_content", severity,
                    f"Content placed after {blank} consecutive blank lines (hidden from casual review)",
                    relative, index + 1, line.strip()[:500], {"blank_lines": blank},
                    "Remove the padding and review the content that follows it.",
                ))
                reported = True
            elif len(line) - len(line.lstrip(" \t")) >= _PAD_RUN and line.strip():
                results.append(_finding(
                    "AG006", "hidden_content", severity,
                    "Content pushed off-screen by long leading whitespace",
                    relative, index + 1, line.strip()[:500], {"leading_whitespace": len(line) - len(line.lstrip())},
                    "Remove the padding and review the content.",
                ))
                reported = True
            blank = 0
        escaped = _ESCAPED_TAG.search(text) if path.suffix.lower() in _CODE_SUFFIXES else None
        if escaped:
            line = _line_of(text, escaped.start())
            results.append(_finding(
                "AG006", "hidden_content", "MEDIUM",
                "Escaped Unicode Tag-block character in code (steganographic instruction channel)",
                relative, line, _snippet(text, line), {"indicator": escaped.group(0)},
                "Tag-block characters (U+E0000-U+E007F) are invisible and have no legitimate use in skills.",
            ))
        invisible = _INVISIBLE.search(text)
        if invisible and not reported:
            results.append(_finding(
                "AG006", "hidden_content", "MEDIUM",
                "Invisible Unicode characters (possible hidden instructions)",
                relative, _line_of(text, invisible.start()), _snippet(text, _line_of(text, invisible.start())),
                {"codepoint": f"U+{ord(invisible.group(0)):04X}"},
                "Strip zero-width, bidirectional-control and tag characters.",
            ))
    return results


# =========================================================================== AG007
def _pyc_strings(data: bytes) -> set[str]:
    return {item.decode("ascii", errors="ignore") for item in re.findall(rb"[A-Za-z_][A-Za-z0-9_.]{3,}", data)}


def _archive_members(data: bytes) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return []


def artifacts(root: Path) -> list[Finding]:
    results = []
    for path in _files(root):
        relative = _rel(path, root)
        suffix = path.suffix.lower()
        try:
            data = path.read_bytes() if path.stat().st_size <= 50 * 1024 * 1024 else path.read_bytes()[:8]
        except OSError:
            continue
        if suffix == ".pyc" or "__pycache__" in path.parts:
            source = path.parent.parent / (path.name.split(".")[0] + ".py")
            source_text = source.read_text(encoding="utf-8", errors="replace") if source.is_file() else ""
            extra = sorted(name for name in _pyc_strings(data)
                           if name in _SUSPICIOUS_PYC_NAMES and name not in source_text)
            if extra:
                results.append(_finding(
                    "AG007", "bytecode_mismatch", "HIGH",
                    "Precompiled bytecode references behaviour absent from its source file",
                    relative, 1, ", ".join(extra), {"names_only_in_bytecode": extra, "source_present": source.is_file()},
                    "Delete __pycache__/*.pyc from the skill. Only reviewable source should be shipped.",
                ))
            else:
                results.append(_finding(
                    "AG007", "bytecode_present", "MEDIUM",
                    "Skill ships precompiled Python bytecode that cannot be reviewed as source",
                    relative, 1, path.name, {}, "Delete __pycache__/*.pyc from the skill.",
                ))
            continue
        head = data[:4]
        if head == b"PK\x03\x04" and suffix not in _ARCHIVE_SUFFIXES:
            members = _archive_members(data)
            scripts = [name for name in members if _SCRIPT_ENTRY.search(name)]
            hidden = path.name.startswith(".")
            results.append(_finding(
                "AG007", "disguised_archive", "HIGH" if scripts or hidden else "MEDIUM",
                "ZIP archive disguised with a non-archive file extension",
                relative, 1, path.name,
                {"members": members[:40], "embedded_scripts": scripts, "hidden_file": hidden},
                "Remove the disguised archive or ship it with an honest extension and document it.",
            ))
        elif suffix in _ARCHIVE_SUFFIXES and head == b"PK\x03\x04":
            scripts = [name for name in _archive_members(data) if _SCRIPT_ENTRY.search(name)]
            if scripts:
                results.append(_finding(
                    "AG007", "archive_with_scripts", "MEDIUM",
                    "Archive contains executable script entries",
                    relative, 1, path.name, {"embedded_scripts": scripts},
                    "Do not ship executable scripts inside office/archive containers.",
                ))
        elif head in {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"} or head[:2] == b"MZ":
            results.append(_finding(
                "AG007", "native_binary", "MEDIUM",
                "Skill ships a native executable binary that cannot be statically reviewed",
                relative, 1, path.name, {"magic": head.hex()},
                "Ship source code instead of compiled binaries.",
            ))
    return results


# =========================================================================== AG008
def supply_chain(root: Path) -> list[Finding]:
    results = []
    for path, text in _text_files(root):
        relative = _rel(path, root)
        seen_hosts: set[str] = set()
        for number, line in enumerate(text.splitlines(), 1):
            if _REGISTRY_LINE.search(line):
                for match in _URL.finditer(line):
                    host = match.group(1).lower().rstrip(".")
                    if host in _OFFICIAL_REGISTRY_HOSTS or host in seen_hosts:
                        continue
                    seen_hosts.add(host)
                    ip_literal = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
                    hostile = ip_literal or host.endswith(_SUSPICIOUS_TLDS)
                    results.append(_finding(
                        "AG008", "supply_chain", "HIGH" if hostile else "MEDIUM",
                        f"Package registry redirected to a non-official host: {host}",
                        relative, number, line.strip()[:500],
                        {"host": host, "suspicious_host": hostile},
                        "Verify the mirror is owned by you, or use the official registry and pin dependencies by hash.",
                    ))
            match = _PIPE_TO_SHELL.search(line)
            if match:
                defensive = path.suffix.lower() in _DOC_SUFFIXES and _defensive(line, match.start())
                results.append(_finding(
                    "AG008", "supply_chain", "LOW" if defensive else "HIGH",
                    "Remote script piped into a shell (mentioned in a warning, not an instruction)"
                    if defensive else "Remote script piped directly into a shell",
                    relative, number, line.strip()[:500],
                    {"indicator": match.group(0)[:200], "defensive_context": defensive},
                    "Download, review and checksum scripts before executing them.",
                ))
            elif _DIRECT_URL_INSTALL.search(line):
                results.append(_finding(
                    "AG008", "supply_chain", "MEDIUM", "Package installed from a direct URL instead of a registry",
                    relative, number, line.strip()[:500], {},
                    "Install pinned packages from the official registry.",
                ))
    return results


# =========================================================================== AG009
def prompt_injection(root: Path) -> list[Finding]:
    results = []
    for path, text in _text_files(root):
        if path.suffix.lower() not in _DOC_SUFFIXES:
            continue
        relative = _rel(path, root)
        reported_lines: set[int] = set()
        for comment in _HTML_COMMENT.finditer(text):
            body = comment.group(1)
            if _COMMENT_INSTRUCTION.search(body):
                line = _line_of(text, comment.start())
                reported_lines.add(line)
                sensitive = bool(_SENSITIVE_PATH.search(body))
                results.append(_finding(
                    "AG009", "prompt_injection", "HIGH" if sensitive or _INJECTION.search(body) else "MEDIUM",
                    "Hidden instruction inside an HTML comment addressed to the agent",
                    relative, line, " ".join(body.split())[:500],
                    {"sensitive_path_referenced": sensitive},
                    "Remove hidden instructions; skill documentation must be visible to the user.",
                ))
        for match in _INJECTION.finditer(text):
            line = _line_of(text, match.start())
            if line in reported_lines or any(abs(line - seen) <= 12 for seen in reported_lines):
                continue
            reported_lines.add(line)
            defensive = _defensive(text, match.start(), match.end(), whole_line=True)
            results.append(_finding(
                "AG009", "prompt_injection", "LOW" if defensive else "MEDIUM",
                "Instruction-override phrase quoted in a warning against it" if defensive
                else "Instruction-override or concealment phrase in skill text",
                relative, line, _snippet(text, line),
                {"phrase": match.group(0)[:200], "defensive_context": defensive},
                "Remove instructions that override agent safety rules or conceal actions from the user.",
            ))
    return results


# =========================================================================== AG010
def decode_and_exec(root: Path) -> list[Finding]:
    results = []
    for path, text in _text_files(root):
        relative = _rel(path, root)
        decoders = set(_DECODER_NAMES)
        for imp in _ALIAS_IMPORT.finditer(text):
            for part in imp.group(1).split(","):
                words = part.strip().split()
                if len(words) == 3 and words[1] == "as" and words[0] in _DECODER_NAMES:
                    decoders.add(words[2])
        for assign in _ALIAS_ASSIGN.finditer(text):
            decoders.add(assign.group(1))
        names = "|".join(sorted(re.escape(name) for name in decoders))
        direct = re.compile(rf"\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:[\w.]+\.)?(?:{names})\s*\(")
        decoded_vars = set(re.findall(rf"^[ \t]*(\w+)[ \t]*=[ \t]*(?:[\w.]+\.)?(?:{names})[ \t]*\(", text, re.M))
        hits: list[tuple[int, str]] = []
        for pattern in (direct, _REMOTE_EXEC, _SHELL_DECODE_EXEC, _JS_DECODE_EXEC):
            for match in pattern.finditer(text):
                hits.append((_line_of(text, match.start()), match.group(0)[:200]))
        for var in decoded_vars:
            for match in re.finditer(rf"\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?{re.escape(var)}\b", text):
                hits.append((_line_of(text, match.start()), match.group(0)[:200]))
        for line, indicator in sorted(set(hits)):
            results.append(_finding(
                "AG010", "obfuscated_execution", "HIGH",
                "Decoded or downloaded data is executed (decode-and-exec chain)",
                relative, line, _snippet(text, line), {"indicator": indicator},
                "Remove dynamic execution of encoded or remote payloads.",
            ))
        if path.suffix.lower() == ".py":
            for match in _DYNAMIC_COMPILE.finditer(text):
                line = _line_of(text, match.start())
                results.append(_finding(
                    "AG010", "obfuscated_execution", "MEDIUM",
                    "Non-literal source is compiled as executable code (dynamic code execution)",
                    relative, line, _snippet(text, line), {"indicator": match.group(0)[:200]},
                    "Avoid compiling caller-supplied or computed source; use a parser or an allow-list instead.",
                ))
    return results


# =========================================================================== AG011
def system_secret_access(root: Path) -> list[Finding]:
    results = []
    for path, text in _text_files(root):
        if path.suffix.lower() not in _CODE_SUFFIXES:
            continue
        for match in _SYSTEM_SECRET.finditer(text):
            line = _line_of(text, match.start())
            critical_file = match.group(0).startswith(("/etc/shadow", "/etc/gshadow", "/etc/sudoers"))
            results.append(_finding(
                "AG011", "sensitive_file_access", "HIGH" if critical_file else "MEDIUM",
                "Code references a system secret file: " + match.group(0),
                _rel(path, root), line, _snippet(text, line), {"indicator": match.group(0)},
                "A skill has no legitimate need to read system password, sudo, or service-account secrets.",
            ))
    return results


def extra_rules(root: Path) -> list[Finding]:
    return (env_harvest(root) + hidden_content(root) + artifacts(root) + supply_chain(root)
            + prompt_injection(root) + decode_and_exec(root) + system_secret_access(root))

