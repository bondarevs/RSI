"""Bounded sanitizer; rejected raw data is never retained or hashed."""
from __future__ import annotations
import base64
from dataclasses import dataclass
import html
import re
from typing import Iterable, Mapping
import unicodedata
from urllib.parse import unquote

MAX_ITEMS, MAX_CHARS, MAX_SOURCE_CHARS, MAX_DIAGNOSTICS, MAX_INPUT_ITEMS = 5, 1200, 4096, 5, 32
_SECRET = re.compile(r"(?:sk_(?:live|test)_[\w-]{12,}|(?:ghp_|github_pat_)[\w-]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[\w-]{10,}|bearer\s+[\w.-]{16,}|api[_ -]?key\s*[:=]|-----BEGIN [A-Z ]*PRIVATE KEY-----|password\b\s*[-:=])", re.I)
_PII = re.compile(r"(?:\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b|\+?\d[\d ()-]{8,}\d|\b\d{1,5}\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd)\b|\b(?:name|имя)\s*[:=])", re.I)
_LOW = re.compile(r"(?<!\d)(?:\d[ -]?){12,}\d(?!\d)")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_INSTRUCTION = re.compile(
    r"(?:"
    r"\b(?:ignore|disregard|override)\b.{0,100}\b(?:instructions?|prompt|policy)\b|"
    r"\b(?:run|delete|upload|send|execute|edit)\s+(?:the\s+)?[\w./-]+\b|"
    r"\bignora\b.{0,100}\binstrucciones\b|\belimina\b.{0,100}\bregistro\b|"
    r"\bignorez\b.{0,100}\binstructions\b|\bsupprimez\b.{0,100}\bjournal\b|"
    r"\bignoriere\b.{0,100}\banweisungen\b|\blosche\b.{0,100}\bprotokoll\b|"
    r"\bignore\b.{0,100}\binstrucoes\b|\bexclua\b.{0,100}\bregistro\b|"
    r"\bигнорируй\b.{0,100}\bинструкц|\bудали\s+|"
    r"\bігноруй\b.{0,100}\bінструкц|\bвидали\s+|"
    r"忽略.{0,100}(?:指令|指示)|删除.{0,100}日志|"
    r"(?:指示.{0,100}無視|無視.{0,100}指示)|削除.{0,100}ログ|"
    r"تجاهل.{0,100}التعليمات|احذف.{0,100}السجل"
    r")",
    re.I | re.S,
)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")
_TASK = re.compile(r"(?:\b(?:task|run|ticket|candidate)[-_ ][A-Za-z0-9]{3,}\b|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b)", re.I)
_PATH = re.compile(r"(?:[A-Za-z]:\\[^\s]+|(?<!\S)/(?:[^\s/]+/)+[^\s]+)")
@dataclass(frozen=True)
class SanitizationResult:
    accepted: tuple[dict[str,str],...]; diagnostics: tuple[dict[str,object],...]; rejected_count:int; truncated_count:int


def _normalized(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
    )


def _unicode_unescape(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1) or match.group(2), 16))

    try:
        return _UNICODE_ESCAPE.sub(replace, value)
    except (ValueError, OverflowError):
        return value


def _variants(text: str) -> tuple[str, ...]:
    """Return a small bounded set of decoded views without retaining raw data."""
    pending = [text]
    admitted: list[str] = []
    seen: set[str] = set()
    while pending and len(admitted) < 12:
        value = pending.pop(0)
        normalized = _normalized(value)
        if normalized in seen:
            continue
        seen.add(normalized)
        admitted.append(normalized)
        for decoded in (
            unquote(normalized),
            html.unescape(normalized),
            _unicode_unescape(normalized),
        ):
            if decoded != normalized and len(decoded) <= MAX_SOURCE_CHARS:
                pending.append(decoded)
        for token in _BASE64.findall(normalized)[:2]:
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if len(decoded) <= MAX_SOURCE_CHARS:
                pending.append(decoded)
    return tuple(admitted)


def _reason(text:str)->str|None:
    if len(text)>MAX_SOURCE_CHARS:return "source-too-long"
    for value in _variants(text):
        if _SECRET.search(value):return "secret"
        if _PII.search(value) and not _UUID.search(value):return "pii"
        if _LOW.search(value) and not _UUID.search(value):return "low-entropy-identifier"
        if _INSTRUCTION.search(value):return "instruction-payload"
    return None
def sanitize_evidence(items:Iterable[object],*,max_items:int=MAX_ITEMS,max_chars:int=MAX_CHARS)->SanitizationResult:
    limit=min(MAX_ITEMS,max(0,max_items)) if isinstance(max_items,int) else MAX_ITEMS
    chars=min(MAX_CHARS,max(1,max_chars)) if isinstance(max_chars,int) else MAX_CHARS
    accepted=[]; diagnostics=[]; rejected=truncated=0
    for index,item in enumerate(items):
        if index>=MAX_INPUT_ITEMS: truncated+=1; break
        if not isinstance(item,Mapping) or set(item)-{"kind","summary"} or not isinstance(item.get("kind"),str) or not isinstance(item.get("summary"),str): reason="invalid-evidence-shape"
        else: reason=_reason(item["kind"]) or _reason(item["summary"])
        if reason:
            rejected+=1
            if len(diagnostics)<MAX_DIAGNOSTICS:diagnostics.append({"index":index,"reason":reason})
        elif len(accepted)>=limit: truncated+=1
        else: accepted.append({"kind":item["kind"][:80],"summary":_PATH.sub("<path>",_TASK.sub("task-<id>",item["summary"]))[:chars]})
    return SanitizationResult(tuple(accepted),tuple(diagnostics),rejected,truncated)
