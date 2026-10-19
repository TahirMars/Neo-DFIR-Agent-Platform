"""样本分析：静态引擎基础行为。"""
from pathlib import Path

from src.tools.sample_analysis.static_engine import build_static_report


def test_build_static_report_hashes_and_strings(tmp_path: Path):
    p = tmp_path / "note.bin"
    p.write_bytes(b"hello-world-foobar\x00" + b"X" * 200)
    r = build_static_report(p, evidence_id="ev-test", inner_path="uploads/note.bin")
    assert r["hashes"]["sha256"] and len(r["hashes"]["sha256"]) == 64
    assert r["hashes"]["md5"]
    assert r["evidence_id"] == "ev-test"
    assert any("hello-world" in s for s in r["strings_preview"])
