"""
graph/ 层测试：
- state：DFIRState reducer 行为
- builder：route_after_supervisor 路由逻辑、图构建、节点完整性
- executor：execute_multi_agent_chat 基本流程（mock 图执行）
- pipelines：list / get 功能（已有 test_agents.py 覆盖一部分，此处补充）
"""
import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ========================================================================
# state reducers
# ========================================================================

class TestStateReducers:
    def test_merge_dict(self):
        from src.graph.state import _merge_dict
        assert _merge_dict({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}
        assert _merge_dict({"a": 1}, {"a": 2}) == {"a": 2}  # b overwrites

    def test_replace(self):
        from src.graph.state import _replace
        assert _replace("old", "new") == "new"
        assert _replace([1], [2, 3]) == [2, 3]
        assert _replace(None, 42) == 42


class TestGraphContext:
    def test_format_session_memory_empty(self):
        from src.graph.context import format_session_memory_for_graph

        assert format_session_memory_for_graph(None) == ""
        assert format_session_memory_for_graph([]) == ""

    def test_format_session_memory_joins_roles(self):
        from src.graph.context import format_session_memory_for_graph

        text = format_session_memory_for_graph(
            [{"role": "user", "content": "你好"}, {"role": "assistant", "content": "您好"}],
        )
        assert "【用户】" in text and "你好" in text
        assert "【助手】" in text and "您好" in text

    def test_compose_agent_user_context(self):
        from src.graph.context import compose_agent_user_context

        out = compose_agent_user_context({
            "context_summary": "证据提示",
            "session_context": "历史摘要",
            "user_message": "当前句",
        })
        assert "证据提示" in out and "历史摘要" in out and "当前句" in out

    def test_compose_truncates_session_when_over_budget(self):
        from src.graph.context import compose_agent_user_context

        long_sess = "x" * 5000
        out = compose_agent_user_context(
            {
                "context_summary": "ev",
                "session_context": long_sess,
                "user_message": "最后一句必须保留",
            },
            max_total_chars=400,
        )
        assert "最后一句必须保留" in out
        assert len(out) <= 450


class TestDFIRStateFields:
    def test_state_has_expected_keys(self):
        from src.graph.state import DFIRState
        annotations = DFIRState.__annotations__
        required_keys = [
            "messages", "case_id", "session_id", "user_message",
            "evidence_ids", "case_memory", "session_context", "context_summary",
            "active_skill_ids", "skills_injection_digest", "skills_system_suffix", "skills_inject_mode",
            "file_classifications",
            "agent_results", "final_report", "error", "use_streaming",
        ]
        for key in required_keys:
            assert key in annotations, f"DFIRState 缺少字段 '{key}'"


# ========================================================================
# route_after_supervisor
# ========================================================================

class TestRouteAfterSupervisor:
    """路由基于 file_classifications 和 agent_results。"""

    def _route(self, classifications: dict, agent_results: dict | None = None):
        from src.agents.supervisor import route_after_supervisor
        state = {
            "file_classifications": classifications,
            "agent_results": agent_results or {},
        }
        return route_after_supervisor(state)

    def test_no_evidence(self):
        assert self._route({}) == "general_chat"
        assert self._route({"log": [], "binary": [], "other": []}) == "general_chat"

    def test_log_only_forensic_pending(self):
        assert self._route({"log": ["a.csv"], "binary": []}) == "forensic_agent"

    def test_binary_only_sample_pending(self):
        assert self._route({"log": [], "binary": ["b.exe"]}) == "sample_agent"

    def test_both_types_forensic_first(self):
        # 有日志且取证未完成时优先 forensic
        assert self._route({"log": ["a.csv"], "binary": ["b.exe"]}) == "forensic_agent"

    def test_forensic_done_sample_pending(self):
        assert self._route(
            {"log": ["a.csv"], "binary": ["b.exe"]},
            {"forensic": {"status": "completed"}},
        ) == "sample_agent"

    def test_both_done_report_pending(self):
        assert self._route(
            {"log": ["a.csv"], "binary": ["b.exe"]},
            {"forensic": {}, "sample": {}},
        ) == "report_generator"

    def test_report_done(self):
        from langgraph.graph import END
        assert self._route(
            {"log": ["a.csv"]},
            {"forensic": {}, "report": {}},
        ) == END

    def test_chat_path_no_evidence(self):
        assert self._route({}) == "general_chat"


# ========================================================================
# build_dfir_graph — 结构正确性
# ========================================================================

class TestBuildDfirGraph:
    def test_graph_nodes(self):
        from src.graph.builder import build_dfir_graph
        graph = build_dfir_graph()
        node_names = set(graph.nodes.keys())
        expected = {"supervisor", "forensic_agent", "sample_agent", "report_generator", "general_chat"}
        assert expected.issubset(node_names), f"缺少节点: {expected - node_names}"

    def test_graph_compiles(self):
        from src.graph.builder import build_dfir_graph
        graph = build_dfir_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_get_compiled_graph_singleton(self):
        from src.graph import builder
        from unittest.mock import patch

        builder._compiled_graph = None
        builder._compiled_graph_checkpointed = None
        with patch.object(builder, "get_settings") as mock_gs:
            mock_gs.return_value.langgraph_checkpoint_enabled = False
            g1 = builder.get_compiled_graph()
            g2 = builder.get_compiled_graph()
            assert g1 is g2
        builder._compiled_graph = None
        builder._compiled_graph_checkpointed = None

    def test_get_compiled_graph_checkpointed_is_distinct_singleton(self):
        from src.graph import builder
        from unittest.mock import patch

        builder._compiled_graph = None
        builder._compiled_graph_checkpointed = None
        with patch.object(builder, "get_settings") as mock_gs:
            mock_gs.return_value.langgraph_checkpoint_enabled = True
            gc = builder.get_compiled_graph()
            gc2 = builder.get_compiled_graph()
            assert gc is gc2
        builder._compiled_graph = None
        builder._compiled_graph_checkpointed = None


# ========================================================================
# executor (mock compiled graph)
# ========================================================================

class TestExecuteMultiAgentChat:
    @pytest.mark.asyncio
    @patch("src.graph.executor.get_compiled_graph")
    async def test_basic_invoke(self, mock_get_graph):
        from src.graph.executor import execute_multi_agent_chat

        mock_compiled = AsyncMock()
        mock_compiled.ainvoke.return_value = {
            "final_report": "这是最终报告",
            "messages": [MagicMock(content="done")],
            "agent_results": {"report": {"status": "completed"}},
            "file_classifications": {},
        }
        mock_get_graph.return_value = mock_compiled

        result = await execute_multi_agent_chat(
            case_id="case-001",
            session_id="session-001",
            user_message="请分析",
        )
        assert result["final_report"] == "这是最终报告"
        assert "report" in result["agent_results"]
        mock_compiled.ainvoke.assert_awaited_once()
        assert "graph_thread_id" not in result

    @pytest.mark.asyncio
    @patch("src.graph.executor.get_compiled_graph")
    @patch("src.graph.executor.get_settings")
    async def test_checkpoint_passes_thread_id_in_config(self, mock_get_settings, mock_get_graph):
        from src.graph.executor import execute_multi_agent_chat

        mock_get_settings.return_value.langgraph_checkpoint_enabled = True
        mock_compiled = AsyncMock()
        mock_compiled.ainvoke.return_value = {
            "final_report": "",
            "messages": [MagicMock(content="ok")],
            "agent_results": {},
            "file_classifications": {},
        }
        mock_get_graph.return_value = mock_compiled

        result = await execute_multi_agent_chat(
            case_id="c",
            session_id="s",
            user_message="hi",
            request_id="req-abc",
        )
        cfg = mock_compiled.ainvoke.call_args.kwargs["config"]
        assert cfg["configurable"]["thread_id"] == "req-abc"
        assert result["graph_thread_id"] == "req-abc"

    @pytest.mark.asyncio
    @patch("src.graph.executor.get_compiled_graph")
    async def test_error_handling(self, mock_get_graph):
        from src.graph.executor import execute_multi_agent_chat

        mock_compiled = AsyncMock()
        mock_compiled.ainvoke.side_effect = RuntimeError("LLM 超时")
        mock_get_graph.return_value = mock_compiled

        result = await execute_multi_agent_chat(
            case_id="case-err",
            session_id="session-err",
            user_message="test",
        )
        assert "出错" in result["explanation"]
        assert result["error"] == "LLM 超时"

    @pytest.mark.asyncio
    @patch("src.graph.executor.get_compiled_graph")
    async def test_with_evidence_ids(self, mock_get_graph):
        from src.graph.executor import execute_multi_agent_chat

        mock_compiled = AsyncMock()
        mock_compiled.ainvoke.return_value = {
            "final_report": "报告内容",
            "messages": [MagicMock(content="ok")],
            "agent_results": {"forensic": {"status": "completed"}},
            "file_classifications": {},
        }
        mock_get_graph.return_value = mock_compiled

        result = await execute_multi_agent_chat(
            case_id="case-002",
            session_id="session-002",
            user_message="分析这个",
            evidence_ids=["ev-001", "ev-002"],
        )
        assert result["final_report"] == "报告内容"
        assert "forensic" in result["agent_results"]

        call_args = mock_compiled.ainvoke.call_args
        initial_state = call_args[0][0]
        assert initial_state["evidence_ids"] == ["ev-001", "ev-002"]
        assert initial_state["session_context"] == ""
        assert initial_state["context_summary"] == ""
        assert initial_state.get("skills_inject_mode") == "full"

    @pytest.mark.asyncio
    @patch("src.graph.executor.get_compiled_graph")
    async def test_session_context_and_summary_in_initial_state(self, mock_get_graph):
        from src.graph.executor import execute_multi_agent_chat

        mock_compiled = AsyncMock()
        mock_compiled.ainvoke.return_value = {
            "final_report": "",
            "messages": [MagicMock(content="ok")],
            "agent_results": {},
            "file_classifications": {},
        }
        mock_get_graph.return_value = mock_compiled

        await execute_multi_agent_chat(
            case_id="case-ctx",
            session_id="session-ctx",
            user_message="本轮",
            session_memory=[{"role": "user", "content": "上一轮问题"}],
            context_summary="【证据】evidence_ids=[e1]",
        )
        initial_state = mock_compiled.ainvoke.call_args[0][0]
        assert "上一轮问题" in initial_state["session_context"]
        assert initial_state["context_summary"] == "【证据】evidence_ids=[e1]"

    @pytest.mark.asyncio
    @patch("src.graph.executor.get_compiled_graph")
    async def test_stream_sink_done_on_error(self, mock_get_graph):
        from src.graph.executor import execute_multi_agent_chat

        mock_compiled = AsyncMock()
        mock_compiled.ainvoke.side_effect = ValueError("boom")
        mock_get_graph.return_value = mock_compiled

        queue = asyncio.Queue()
        await execute_multi_agent_chat(
            case_id="c", session_id="s", user_message="x",
            stream_sink=queue,
        )
        msg = await queue.get()
        assert msg == ("done", None)

    @pytest.mark.asyncio
    @patch("src.graph.executor.get_compiled_graph")
    async def test_streaming_mode_uses_astream(self, mock_get_graph):
        """流式模式下调用 astream 而非 ainvoke，agent_event 和 chunk 正确推入队列。"""
        from src.graph.executor import execute_multi_agent_chat

        final_state = {
            "final_report": "流式报告",
            "messages": [MagicMock(content="ok")],
            "agent_results": {},
            "file_classifications": {},
        }

        async def fake_astream(initial, config=None, stream_mode=None):
            yield ("updates", {"supervisor": {"file_classifications": {"log": [], "binary": []}}})
            yield ("custom", {"type": "agent_start", "agent": "supervisor"})
            yield ("custom", {"type": "token", "agent": "supervisor", "content": "分析中"})
            yield ("custom", {"type": "agent_end", "agent": "supervisor"})
            yield ("values", final_state)

        mock_compiled = MagicMock()
        mock_compiled.astream = fake_astream
        mock_get_graph.return_value = mock_compiled

        queue = asyncio.Queue()
        result = await execute_multi_agent_chat(
            case_id="c", session_id="s", user_message="test",
            stream_sink=queue, use_streaming=True,
        )

        events = []
        while not queue.empty():
            events.append(await queue.get())

        agent_events = [e for e in events if e[0] == "agent_event"]
        chunks = [e for e in events if e[0] == "chunk"]
        graph_steps = [e for e in events if e[0] == "graph_step"]
        done_events = [e for e in events if e[0] == "done"]

        assert len(graph_steps) == 1
        assert graph_steps[0][1]["node"] == "supervisor"
        assert "file_classifications" in graph_steps[0][1]["keys"]

        assert len(agent_events) == 2
        assert agent_events[0][1]["type"] == "agent_start"
        assert agent_events[1][1]["type"] == "agent_end"
        assert len(chunks) == 1
        assert chunks[0][1]["content"] == "分析中"
        assert len(done_events) == 1
        assert result["final_report"] == "流式报告"

    @pytest.mark.asyncio
    @patch("src.graph.executor.get_compiled_graph")
    async def test_empty_messages_fallback(self, mock_get_graph):
        from src.graph.executor import execute_multi_agent_chat

        mock_compiled = AsyncMock()
        mock_compiled.ainvoke.return_value = {
            "final_report": "",
            "messages": [],
            "agent_results": {},
            "file_classifications": {},
        }
        mock_get_graph.return_value = mock_compiled

        result = await execute_multi_agent_chat(
            case_id="c", session_id="s", user_message="hi",
        )
        assert result["explanation"] == ""


# ========================================================================
# pipelines 补充测试
# ========================================================================

class TestPipelinesModule:
    def test_pipeline_steps_are_strings(self):
        from src.pipeline.templates import list_pipelines
        for p in list_pipelines():
            for step in p["steps"]:
                assert isinstance(step, str), f"Pipeline {p['id']} step 应为字符串"
            assert any("report" in s for s in p["steps"]), f"Pipeline {p['id']} 应包含报告步骤"

    def test_pipeline_ids_unique(self):
        from src.pipeline.templates import list_pipelines
        ids = [p["id"] for p in list_pipelines()]
        assert len(ids) == len(set(ids))
