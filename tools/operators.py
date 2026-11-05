#!/usr/bin/env python3
"""Одно имя оператора для манифеста, каталогов runs/ и наблюдений.

Оператор живёт в трёх местах: ключ `configs/release.json` (`rostelecom`),
каталог `runs/<оператор>/` и поле `operator` в записях `check_pairs.py`.
Поле пишется руками, поэтому встречаются `Megafon`, `ROSTELECOM`,
`Ростелеком`. Читать его нужно терпимо, но файлы не переписывать: в
наблюдениях остаётся то, что было записано в момент прогона, а приведение
к ключу манифеста делается при чтении.
"""
import json
from pathlib import Path
from typing import Any, Dict, Optional


def slug(name: str) -> str:
    """«Sber Mobile» → sber-mobile: одно имя на папку runs/ и ключ манифеста."""
    cleaned = "".join(ch if ch.isalnum() or ch in " -_" else "" for ch in name.lower())
    return "-".join(cleaned.replace("_", " ").split()) or "unknown"


def load_manifest(path: Path) -> Dict[str, Any]:
    """Манифест операторов; пустой словарь, если файла нет или он битый."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _aliases(manifest: Dict[str, Any]) -> Dict[str, str]:
    """Нормализованное имя (ключ или title) → ключ манифеста."""
    aliases: Dict[str, str] = {}
    for key, spec in manifest.items():
        aliases[slug(key)] = key
        title = (spec or {}).get("title") if isinstance(spec, dict) else None
        if title:
            aliases.setdefault(slug(title), key)
    return aliases


def canonical_key(value: Optional[str], manifest: Dict[str, Any]) -> str:
    """Ключ манифеста для записанного имени оператора.

    Неизвестный оператор возвращается своим слагом: он мог проверяться
    вручную и ещё не попасть в манифест.
    """
    if not value or not str(value).strip():
        return ""
    key = slug(str(value))
    return _aliases(manifest or {}).get(key, key)


def display(key: str, manifest: Dict[str, Any]) -> str:
    """Человеческое название оператора для отчётов."""
    spec = (manifest or {}).get(key)
    if isinstance(spec, dict) and spec.get("title"):
        return str(spec["title"])
    return key
