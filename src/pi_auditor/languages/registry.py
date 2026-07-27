"""Registry and automatic selection for installed language packs."""

from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Tuple

from .base import LanguagePack
from .ar import PACK as ARABIC_PACK
from .en import PACK as ENGLISH_PACK
from .ru import PACK as RUSSIAN_PACK

_PACKS: "OrderedDict[str, LanguagePack]" = OrderedDict()


def register_language_pack(pack: LanguagePack, *, replace: bool = False) -> None:
    code = pack.code.lower().strip()
    if not code or code != pack.code:
        raise ValueError("language pack code must be lowercase and non-empty")
    if code in _PACKS and not replace:
        raise ValueError(f"language pack already registered: {code}")
    _PACKS[code] = pack


def unregister_language_pack(code: str) -> LanguagePack:
    try:
        return _PACKS.pop(code.lower())
    except KeyError as error:
        raise KeyError(f"unknown language pack: {code}") from error


def get_language_pack(code: str) -> LanguagePack:
    try:
        return _PACKS[code.lower()]
    except KeyError as error:
        raise KeyError(f"unknown language pack: {code}") from error


def list_language_packs() -> Tuple[LanguagePack, ...]:
    return tuple(_PACKS.values())


def detect_languages(text: str, *, threshold: float = 0.15) -> List[Tuple[LanguagePack, float]]:
    detected = [(pack, pack.confidence(text)) for pack in _PACKS.values()]
    detected = [(pack, score) for pack, score in detected if score >= threshold]
    return sorted(detected, key=lambda item: item[1], reverse=True)


def resolve_language_packs(text: str, languages: Optional[Iterable[str]] = None) -> Tuple[LanguagePack, ...]:
    if languages is not None:
        seen = set()
        resolved = []
        for code in languages:
            pack = get_language_pack(code)
            if pack.code not in seen:
                seen.add(pack.code)
                resolved.append(pack)
        return tuple(resolved)
    detected = detect_languages(text)
    # English remains the fallback because the generic built-in rule corpus is
    # English-centric. Mixed text can return several packs.
    return tuple(pack for pack, _ in detected) or (ENGLISH_PACK,)


register_language_pack(ENGLISH_PACK)
register_language_pack(ARABIC_PACK)
register_language_pack(RUSSIAN_PACK)
