"""案件记忆：append / 章节提取（跨节点需磁盘刷新，见 forensic/sample/report 节点）。"""
import concurrent.futures
from pathlib import Path


class _FakeSettings:
    case_memory_auto_init_enabled = False

    def __init__(self, root: Path):
        self._root = root

    def workspace_root_dir(self) -> Path:
        return self._root


def test_append_case_memory_same_section_accumulates(tmp_path, monkeypatch):
    from src.agents.middleware import memory as mem

    monkeypatch.setattr(mem, "get_settings", lambda: _FakeSettings(tmp_path))

    cid = "case-append-1"
    mem.append_case_memory(cid, "分析进展", "第一条")
    mem.append_case_memory(cid, "分析进展", "第二条")
    text = mem.load_case_memory(cid)
    assert "第一条" in text
    assert "第二条" in text
    assert text.count("- [") >= 2


def test_append_parallel_same_section_no_lost_updates(tmp_path, monkeypatch):
    """并行多次 append 时不得互相覆盖（典型：同一轮多个 case_memory_update）。"""
    from src.agents.middleware import memory as mem

    monkeypatch.setattr(mem, "get_settings", lambda: _FakeSettings(tmp_path))

    cid = "case-parallel-1"

    def one(i: int) -> None:
        mem.append_case_memory(cid, "分析进展", f"并行条目{i}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(one, range(12)))

    text = mem.load_case_memory(cid)
    for i in range(12):
        assert f"并行条目{i}" in text, f"missing parallel item {i}"


def test_extract_case_memory_section(tmp_path, monkeypatch):
    from src.agents.middleware import memory as mem

    monkeypatch.setattr(mem, "get_settings", lambda: _FakeSettings(tmp_path))

    cid = "case-extract-1"
    mem.append_case_memory(cid, "已确认 IOC", "a.com")
    mem.append_case_memory(cid, "已确认 IOC", "b.com")
    full = mem.load_case_memory(cid)
    sec = mem.extract_case_memory_section(full, "已确认 IOC")
    assert "## 已确认 IOC" in sec
    assert "a.com" in sec
    assert "b.com" in sec
    assert "## 分析进展" not in sec
