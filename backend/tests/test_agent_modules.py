"""
agents/ 拆分后各模块单元测试：
- prompts：所有提示词存在且非空
- tools：工具工厂返回正确数量和类型的工具
- llm：get_chat_model / make_stream_helpers / build_messages
- supervisor / forensic / sample / report / chat：节点函数签名与基本逻辑
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ========================================================================
# prompts
# ========================================================================

class TestPrompts:
    def test_all_prompts_exist_and_nonempty(self):
        from src.agents.prompts import (
            SUPERVISOR_SYSTEM_PROMPT,
            FORENSIC_ANALYSIS_PROMPT,
            SAMPLE_ANALYSIS_PROMPT,
            REPORT_GENERATION_PROMPT,
            DEFAULT_CHAT_PROMPT,
        )
        for name, prompt in [
            ("SUPERVISOR", SUPERVISOR_SYSTEM_PROMPT),
            ("FORENSIC", FORENSIC_ANALYSIS_PROMPT),
            ("SAMPLE", SAMPLE_ANALYSIS_PROMPT),
            ("REPORT", REPORT_GENERATION_PROMPT),
            ("DEFAULT", DEFAULT_CHAT_PROMPT),
        ]:
            assert isinstance(prompt, str), f"{name} should be str"
            assert len(prompt) > 50, f"{name} prompt is too short"

    def test_supervisor_prompt_mentions_sub_agents(self):
        from src.agents.prompts import SUPERVISOR_SYSTEM_PROMPT
        # 提示词中提及委派工具（多节点图下 Supervisor 不再调用 LLM，但提示词仍保留供 registry）
        assert "delegate_to_forensic" in SUPERVISOR_SYSTEM_PROMPT or "取证" in SUPERVISOR_SYSTEM_PROMPT
        assert "delegate_to_sample" in SUPERVISOR_SYSTEM_PROMPT or "样本" in SUPERVISOR_SYSTEM_PROMPT
        assert "generate_report" in SUPERVISOR_SYSTEM_PROMPT or "报告" in SUPERVISOR_SYSTEM_PROMPT


# ========================================================================
# tools
# ========================================================================

class TestToolFactories:
    def test_create_forensic_tools(self):
        from src.agents.tools import create_forensic_tools
        tools = create_forensic_tools("case1", ["ev1"], "sess1", [{"path": "a.csv", "size": 100, "ext": ".csv"}])
        names = [t.name for t in tools]
        assert "evidence_ls_tool" in names
        assert "evidence_read_tool" in names
        assert "evidence_grep_tool" in names
        assert "get_evidence_info" in names
        assert "list_log_files" not in names
        assert "read_log_file" not in names
        assert "parse_structured_log" not in names

    def test_forensic_evidence_ls_classified_only(self):
        from src.agents.tools import create_forensic_tools
        log_files = [
            {"path": "logs/a.csv", "size": 2048, "ext": ".csv"},
            {"path": "logs/b.log", "size": 512, "ext": ".log"},
        ]
        tools = create_forensic_tools("c1", ["e1"], "s1", log_files)
        ls_tool = next(t for t in tools if t.name == "evidence_ls_tool")
        result = ls_tool.invoke({"evidence_id": "e1", "only_classified_logs": True})
        assert "logs/a.csv" in result or "无匹配" in result or "不存在" in result

    def test_forensic_evidence_ls_empty_classified(self):
        from src.agents.tools import create_forensic_tools
        tools = create_forensic_tools("c1", ["e1"], "s1", [])
        ls_tool = next(t for t in tools if t.name == "evidence_ls_tool")
        result = ls_tool.invoke({"evidence_id": "e1", "only_classified_logs": True})
        assert "主管分类结果为空" in result

    def test_create_sample_tools(self):
        from src.agents.tools import create_sample_tools
        tools = create_sample_tools("case1", ["ev1"], "sess1", [{"path": "bad.exe", "size": 1024, "ext": ".exe"}])
        names = [t.name for t in tools]
        assert "list_binary_files" in names
        assert "run_static_analysis" in names
        assert "run_dynamic_analysis" in names
        assert "read_binary_file_metadata" in names

    def test_sample_read_metadata_tool(self):
        from src.agents.tools import create_sample_tools
        binary_files = [{"path": "malware.exe", "size": 4096, "ext": ".exe"}]
        tools = create_sample_tools("c1", ["e1"], "s1", binary_files)
        meta_tool = next(t for t in tools if t.name == "read_binary_file_metadata")
        result = meta_tool.invoke({"file_path": "malware.exe"})
        assert "malware.exe" in result
        assert "4096" in result

    def test_sample_read_metadata_not_found(self):
        from src.agents.tools import create_sample_tools
        tools = create_sample_tools("c1", ["e1"], "s1", [])
        meta_tool = next(t for t in tools if t.name == "read_binary_file_metadata")
        result = meta_tool.invoke({"file_path": "ghost.exe"})
        assert "未找到" in result

    def test_create_report_tools(self):
        from src.agents.tools import create_report_tools
        tools = create_report_tools("case1", ["ev1"], "sess1")
        names = [t.name for t in tools]
        assert "get_evidence_summary" in names


# ========================================================================
# llm helpers
# ========================================================================

class TestLlmHelpers:
    def test_normalize_message_content_str(self):
        from src.agents.llm import normalize_message_content
        assert normalize_message_content("hello") == "hello"
        assert normalize_message_content(None) == ""

    def test_normalize_message_content_multimodal_list(self):
        from src.agents.llm import normalize_message_content
        blocks = [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]
        assert normalize_message_content(blocks) == "ab"

    def test_extract_chunk_text_string_content(self):
        from src.agents.llm import extract_chunk_text
        class C:
            content = "x"
        assert extract_chunk_text(C()) == "x"

    def test_make_stream_helpers_disabled(self):
        from src.agents.llm import make_stream_helpers
        writer, cb = make_stream_helpers({"use_streaming": False}, "test")
        assert writer is None
        assert cb is None

    def test_make_stream_helpers_missing_key(self):
        from src.agents.llm import make_stream_helpers
        writer, cb = make_stream_helpers({}, "test")
        assert writer is None
        assert cb is None


# ========================================================================
# supervisor node logic
# ========================================================================

class TestSupervisorNode:
    """测试 supervisor 节点的证据分类逻辑（多节点图架构）。"""

    @pytest.mark.asyncio
    @patch("src.agents.supervisor.classify_evidence_files", return_value={"binary": [], "log": [{"path": "a.csv", "ext": ".csv", "size": 100}], "other": []})
    async def test_classify_with_log_files(self, mock_classify):
        from src.agents.supervisor import supervisor_node
        state = {
            "evidence_ids": ["ev-001"],
            "use_streaming": False,
        }
        result = await supervisor_node(state)
        assert "file_classifications" in result
        assert result["file_classifications"].get("log")
        assert len(result["file_classifications"]["log"]) == 1

    @pytest.mark.asyncio
    @patch("src.agents.supervisor.classify_evidence_files", return_value={"binary": [{"path": "b.exe", "ext": ".exe", "size": 200}], "log": [{"path": "a.csv", "ext": ".csv", "size": 100}], "other": []})
    async def test_classify_both_types(self, mock_classify):
        from src.agents.supervisor import supervisor_node
        state = {
            "evidence_ids": ["ev-002"],
            "use_streaming": False,
        }
        result = await supervisor_node(state)
        assert "log" in result["file_classifications"]
        assert "binary" in result["file_classifications"]
        assert len(result["file_classifications"]["log"]) == 1
        assert len(result["file_classifications"]["binary"]) == 1

    @pytest.mark.asyncio
    async def test_classify_no_evidence(self):
        from src.agents.supervisor import supervisor_node
        state = {
            "evidence_ids": [],
            "use_streaming": False,
        }
        result = await supervisor_node(state)
        assert result.get("file_classifications") == {}

    @pytest.mark.asyncio
    async def test_classify_skipped_when_already_classified(self):
        from src.agents.supervisor import supervisor_node
        state = {
            "evidence_ids": ["ev-001"],
            "file_classifications": {"log": ["pre"], "binary": [], "other": []},
            "use_streaming": False,
        }
        result = await supervisor_node(state)
        # 已有分类时不再调用 classify，返回原样
        assert result["file_classifications"]["log"] == ["pre"]


# ========================================================================
# chat node
# ========================================================================

class TestChatNode:
    @pytest.mark.asyncio
    @patch("src.agents.chat.run_chat_agent", new_callable=AsyncMock, return_value={"status": "completed", "reply": "这是一个DFIR建议", "tool_calls": []})
    async def test_general_chat(self, mock_run):
        from src.agents.chat import general_chat_node
        state = {"user_message": "什么是勒索软件", "use_streaming": False}
        result = await general_chat_node(state)
        assert "DFIR" in result["final_report"]
        assert len(result["messages"]) == 1
        assert "general_chat" in result.get("agent_results", {})
