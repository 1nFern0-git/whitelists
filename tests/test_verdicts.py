"""Проверки без сети: разбор доменов, вердикты, контроль типа фильтрации."""
import json

import pytest

from conftest import load

check_domains = load("check_domains_mod", "check-domains.py")
check_pairs = load("check_pairs_mod", "check_pairs.py")
classify = load("classify_mod", "classify.py")


# --- разбор домена из строки файла -----------------------------------------

@pytest.mark.parametrize("line, expected", [
    ("yandex.ru", "yandex.ru"),
    ("  Yandex.RU  ", "yandex.ru"),
    ("https://mail.ru/inbox", "mail.ru"),
    ("http://2gis.ru?q=1", "2gis.ru"),
    ("vk.com:443", "vk.com"),
    ("# комментарий", ""),
    ("", ""),
    ("мусор с пробелом", ""),
    ("*.wildcard.ru", ""),
    ("test.c", ""),
    ("xn--d1acpjx3f.xn--p1ai", "xn--d1acpjx3f.xn--p1ai"),
])
def test_extract_domain(line, expected):
    assert check_domains.extract_domain(line) == expected


# --- вердикт адреса --------------------------------------------------------

@pytest.mark.parametrize("passes, attempts, threshold, min_attempts, expected", [
    (0, 3, 0.7, 2, classify.ADR_BLOCKED),
    (1, 1, 0.7, 2, classify.ADR_UNSTABLE),      # попыток меньше минимума
    (2, 2, 0.7, 2, classify.ADR_ALLOWED),
    (4, 6, 0.7, 2, classify.ADR_UNSTABLE),      # 0.67 < 0.7
    (5, 6, 0.7, 2, classify.ADR_ALLOWED),
])
def test_address_verdict(passes, attempts, threshold, min_attempts, expected):
    assert classify.address_verdict(passes, attempts, threshold, min_attempts) == expected


def test_threshold_follows_control():
    class Args:
        min_ratio = 0.8
        control_factor = 0.75

    # Канал теряет 17 % — порог ниже абсолютного.
    assert classify.effective_threshold(Args, 0.83) == pytest.approx(0.6225)
    # Канал чист — порог упирается в абсолютный.
    assert classify.effective_threshold(Args, 1.0) == pytest.approx(0.75)
    # Эталона нет — только абсолютный.
    assert classify.effective_threshold(Args, 0.0) == pytest.approx(0.8)


# --- вердикт домена: доля HTTP считается по HTTP-прогонам -------------------

def _args(tmp_path, **overrides):
    import argparse
    args = argparse.Namespace(
        min_ratio=0.8, control_factor=0.75, min_attempts=2, min_http=0.9,
        control_file="", phase="on", runs_dir="", operator="test",
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def _pairs_file(tmp_path, name, records):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def _matrix(domain, ip, passes):
    return {"probe": "matrix", "domain": domain, "ip": ip,
            "attempts": 2, "pass_count": passes}


def test_http_ratio_uses_http_runs_not_all_runs(tmp_path):
    """3 прогона пар, 2 файла HTTP: домен подтверждён, а не «2/3 < 0.9»."""
    runs = [_pairs_file(tmp_path, f"r{i}-pairs.jsonl", [_matrix("a.ru", "1.1.1.1", 2)])
            for i in range(3)]
    http = []
    for i in range(2):
        path = tmp_path / f"r{i}-http.txt"
        path.write_text("a.ru\n", encoding="utf-8")
        http.append(path)

    data = classify.build(runs, http, _args(tmp_path))

    assert data["domains"]["a.ru"]["verdict"] == classify.VERDICT_ALLOWED
    assert data["domains"]["a.ru"]["http"] == 1.0


def test_no_http_files_means_no_content_filter(tmp_path):
    """Без HTTP-шага вердикт ставится по парам, а не «содержимое не подтверждено»."""
    runs = [_pairs_file(tmp_path, "r0-pairs.jsonl", [_matrix("a.ru", "1.1.1.1", 2)])]

    data = classify.build(runs, [], _args(tmp_path))

    assert data["domains"]["a.ru"]["verdict"] == classify.VERDICT_ALLOWED
    assert data["domains"]["a.ru"]["http"] is None


def test_domain_without_address_goes_to_not_measured(tmp_path):
    runs = [_pairs_file(tmp_path, "r0-pairs.jsonl", [
        _matrix("a.ru", "1.1.1.1", 2),
        {"probe": "matrix", "domain": "dead.example", "ip": "", "attempts": 1,
         "pass_count": 0, "status": "DNS_NX"},
    ])]
    http = [tmp_path / "r0-http.txt"]
    http[0].write_text("a.ru\n", encoding="utf-8")

    data = classify.build(runs, http, _args(tmp_path))

    assert data["domains"]["dead.example"]["verdict"] == classify.VERDICT_UNKNOWN


# --- контроль типа фильтрации ----------------------------------------------

def test_control_without_contrast_is_not_pair():
    """Ни одного заблокированного: 0/0 — это «нечего сравнивать», не «pair»."""
    records = [{"probe": "matrix", "domain": "a.ru", "ip": "1.1.1.1",
                "status": check_pairs.STATUS_PASS}]
    args = type("Args", (), {"control": True, "control_sample": 5})()

    import asyncio
    extra, result = asyncio.run(check_pairs.run_controls(records, args, {}, None))

    assert extra == []                                  # контроль не запускался
    assert result["verdict"] == "no_contrast"
    assert result["ip_control_ratio"] is None
    assert result["sni_control_ratio"] is None
    assert result["passed_pairs"] == 1


def test_control_off_is_reported_as_no_control():
    args = type("Args", (), {"control": False, "control_sample": 5})()
    import asyncio
    _, result = asyncio.run(check_pairs.run_controls([], args, {}, None))
    assert result["verdict"] == "no_data"      # пар нет вовсе
