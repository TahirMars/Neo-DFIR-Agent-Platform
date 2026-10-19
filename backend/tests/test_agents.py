"""智能体注册表、流水线模板与 Agent 列表 API 测试。"""
import pytest


class TestAgentRegistry:
    """单元测试：智能体注册表。"""

    def test_list_agent_types(self):
        from src.agents.registry import list_agent_types
        types = list_agent_types()
        assert isinstance(types, list)
        assert len(types) >= 4
        type_values = [t.value if hasattr(t, "value") else str(t) for t in types]
        assert "supervisor" in type_values
        assert "forensic" in type_values
        assert "sample" in type_values
        assert "report" in type_values
        assert "default" in type_values

    def test_get_supervisor_config(self):
        from src.agents.registry import get_agent_config
        cfg = get_agent_config("supervisor")
        assert cfg["name"] == "主管智能体"
        assert "system_prompt" in cfg
        assert len(cfg["system_prompt"]) > 100
        assert cfg["max_tokens"] > 0

    def test_get_forensic_config(self):
        from src.agents.registry import get_agent_config
        cfg = get_agent_config("forensic")
        assert cfg["name"] == "取证分析智能体"
        assert "IOC" in cfg["system_prompt"]

    def test_get_unknown_agent_falls_back(self):
        from src.agents.registry import get_agent_config
        cfg = get_agent_config("nonexistent_agent")
        assert cfg["name"] == "DFIR 助手"

    def test_each_agent_has_prompt(self):
        from src.agents.registry import get_agent_config, list_agent_types
        for t in list_agent_types():
            cfg = get_agent_config(t)
            assert cfg.get("system_prompt"), f"Agent {t} 缺少 system_prompt"
            assert cfg.get("name"), f"Agent {t} 缺少 name"


class TestAgentCommon:
    """单元测试：AgentContext / AgentResult。"""

    def test_agent_context_defaults(self):
        from src.agents.common import AgentContext
        ctx = AgentContext()
        assert ctx.case_id == ""
        assert ctx.session_memory == []
        assert ctx.evidence_ids == []

    def test_agent_context_with_values(self):
        from src.agents.common import AgentContext
        ctx = AgentContext(case_id="c1", session_id="s1", user_message="hello")
        assert ctx.case_id == "c1"
        assert ctx.user_message == "hello"

    def test_agent_result_to_dict(self):
        from src.agents.common import AgentResult
        result = AgentResult(agent_type="forensic", explanation="发现可疑 IP", iocs=[{"ip": "1.2.3.4"}])
        d = result.to_dict()
        assert d["agent_type"] == "forensic"
        assert d["explanation"] == "发现可疑 IP"
        assert len(d["iocs"]) == 1

    def test_agent_type_enum(self):
        from src.agents.common import AgentType
        assert AgentType.supervisor.value == "supervisor"
        assert AgentType.forensic.value == "forensic"
        assert AgentType.sample.value == "sample"
        assert AgentType.report.value == "report"
        assert AgentType.default.value == "default"


class TestPipelineLoader:
    """单元测试：流水线模板。"""

    def test_list_pipelines(self):
        from src.pipeline.templates import list_pipelines
        pipes = list_pipelines()
        assert len(pipes) >= 4
        ids = [p["id"] for p in pipes]
        assert "single_host_quick" in ids
        assert "full_investigation" in ids

    def test_get_pipeline(self):
        from src.pipeline.templates import get_pipeline
        p = get_pipeline("single_host_quick")
        assert p is not None
        assert p["name"] == "单主机快速分析"
        assert "steps" in p
        assert len(p["steps"]) > 0

    def test_get_nonexistent_pipeline(self):
        from src.pipeline.templates import get_pipeline
        assert get_pipeline("nonexistent") is None

    def test_each_pipeline_has_required_fields(self):
        from src.pipeline.templates import list_pipelines
        for p in list_pipelines():
            assert "id" in p
            assert "name" in p
            assert "description" in p
            assert "steps" in p
            assert isinstance(p["steps"], list)


class TestAgentsAPI:
    """集成测试：/api/v1/pipelines 与 /api/v1/agents。"""

    def test_list_pipelines_api(self, client, admin_headers):
        resp = client.get("/api/v1/pipelines", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 4

    def test_list_agents_api(self, client, admin_headers):
        resp = client.get("/api/v1/agents", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 4
        names = [a["name"] for a in data["items"]]
        assert "主管智能体" in names
        assert "取证分析智能体" in names
