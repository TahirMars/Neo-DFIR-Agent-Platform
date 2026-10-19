"""session_persistence：工作区落盘（analysis_runs、快照）。"""
from pathlib import Path

import pytest


class _FakeSettings:
    session_workspace_persistence_enabled = True
    session_memory_single_msg_max_chars = 4000
    context_memory_light_append_chars = 12_000
    context_memory_trigger_chars = 60_000
    session_run_artifact_max_chars_per_block = 2000

    def __init__(self, root: Path):
        self._root = root

    def workspace_root_dir(self) -> Path:
        return self._root


@pytest.fixture
def fake_root(tmp_path: Path):
    return tmp_path


def test_append_analysis_run_creates_artifact(fake_root, monkeypatch):
    from src.agents.middleware import session_persistence as sp

    monkeypatch.setattr(sp, "get_settings", lambda: _FakeSettings(fake_root))
    sp.append_analysis_run_artifact(
        "case-a",
        "sess-b",
        user_message="用户问题",
        evidence_ids=["ev-1"],
        result={
            "explanation": "最终说明",
            "final_report": "",
            "agent_results": {
                "forensic": {"status": "completed", "analysis": "发现 IOC x"},
            },
        },
        use_langgraph=True,
    )
    p = fake_root / "case-a" / "sessions" / "sess-b" / "artifacts" / "analysis_runs.md"
    assert p.is_file()
    text = p.read_text(encoding="utf-8")
    assert "用户问题" in text and "ev-1" in text and "最终说明" in text and "forensic" in text


def test_persist_disabled_skips_write(fake_root, monkeypatch):
    from src.agents.middleware import session_persistence as sp

    class Off(_FakeSettings):
        session_workspace_persistence_enabled = False

    monkeypatch.setattr(sp, "get_settings", lambda: Off(fake_root))
    sp.append_analysis_run_artifact(
        "c", "s",
        user_message="x",
        evidence_ids=[],
        result={"explanation": "y"},
        use_langgraph=False,
    )
    assert not (fake_root / "c" / "sessions" / "s" / "artifacts").exists()
