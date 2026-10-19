"""Neo Skills：解析、注册表、注入。"""
from pathlib import Path
from unittest.mock import patch

import pytest


class TestSkillParser:
    def test_parse_builtin_sample(self):
        from src.skills.parser import parse_skill_file
        from src.skills.registry import _BUILTIN_DIR

        p = Path(_BUILTIN_DIR) / "dfir-report-checklist" / "SKILL.md"
        doc = parse_skill_file(p, skill_id_fallback="x", source="builtin")
        assert doc is not None
        assert doc.meta.id == "dfir-report-checklist"
        assert "检查项" in doc.body_markdown


class TestSkillRegistry:
    def test_builtin_contains_expected_ids(self):
        from src.skills.registry import SkillRegistry

        r = SkillRegistry()
        ids = {m.id for m in r.list_builtin_metas()}
        assert "dfir-report-checklist" in ids
        assert "dfir-log-triage" in ids

    def test_list_all_metas_for_case_includes_builtin(self):
        from src.skills.registry import SkillRegistry

        r = SkillRegistry()
        ids = {m.id for m in r.list_all_metas_for_case("")}
        assert "dfir-report-checklist" in ids

    def test_resolve_unknown_id(self):
        from src.skills.registry import SkillRegistry

        r = SkillRegistry()
        docs, unknown = r.resolve_documents(["dfir-report-checklist", "not-real-id"], "")
        assert len(docs) == 1
        assert unknown == ["not-real-id"]


class TestSkillInjector:
    def test_empty_when_no_ids(self):
        from src.skills.injector import build_skills_system_suffix

        assert build_skills_system_suffix({"active_skill_ids": [], "case_id": ""}) == ""

    @patch("src.skills.injector.get_settings")
    def test_injects_body_for_valid_id(self, mock_gs):
        from src.skills.injector import build_skills_system_suffix

        mock_gs.return_value.skills_enabled = True
        mock_gs.return_value.skills_description_max_chars = 320
        mock_gs.return_value.skills_body_max_chars = 8000

        block = build_skills_system_suffix({
            "active_skill_ids": ["dfir-report-checklist"],
            "case_id": "",
        })
        assert "Neo Skills" in block
        assert "dfir-report-checklist" in block
        assert "检查项" in block

    @patch("src.skills.injector.get_settings")
    def test_catalog_only_skips_body(self, mock_gs):
        from src.skills.injector import build_skills_system_suffix

        mock_gs.return_value.skills_enabled = True
        mock_gs.return_value.skills_description_max_chars = 320
        mock_gs.return_value.skills_body_max_chars = 8000
        mock_gs.return_value.skills_default_inject_mode = "full"

        block = build_skills_system_suffix({
            "active_skill_ids": ["dfir-report-checklist"],
            "case_id": "",
            "skills_inject_mode": "catalog_only",
        })
        assert "load_skill" in block
        assert "## 技能正文" not in block
        assert "检查项" not in block

    @patch("src.skills.injector.get_settings")
    def test_for_agent_filters_skills(self, mock_gs):
        from src.skills.injector import build_skills_system_suffix

        mock_gs.return_value.skills_enabled = True
        mock_gs.return_value.skills_description_max_chars = 320
        mock_gs.return_value.skills_body_max_chars = 8000

        block_sample = build_skills_system_suffix(
            {
                "active_skill_ids": ["dfir-report-checklist", "dfir-log-triage"],
                "case_id": "",
            },
            for_agent="sample",
        )
        assert block_sample == ""

        block_report = build_skills_system_suffix(
            {
                "active_skill_ids": ["dfir-report-checklist", "dfir-log-triage"],
                "case_id": "",
            },
            for_agent="report",
        )
        assert "dfir-report-checklist" in block_report
        assert "dfir-log-triage" not in block_report


class TestSkillRouter:
    @patch("src.skills.router.match_rule_skill_ids", return_value=[])
    def test_resolve_dedupes(self, _mock_rules):
        from src.skills.router import resolve_active_skill_ids

        assert resolve_active_skill_ids(["a", "a", " b ", ""], "case-1") == ["a", "b"]

    @patch("src.skills.routing_rules.get_settings")
    @patch("src.skills.router.get_settings")
    def test_routing_prepends_rule_skills(self, mock_router_gs, mock_routing_gs):
        from pathlib import Path
        from unittest.mock import MagicMock

        from src.skills.routing_rules import clear_routing_rules_cache
        from src.skills.router import resolve_active_skill_ids

        p = Path(__file__).resolve().parent / "_tmp_skills_routing_test.yaml"
        p.write_text(
            "rules:\n"
            "  - match:\n"
            "      case_name_substrings: [\"勒索\"]\n"
            "    skill_ids: [dfir-report-checklist]\n",
            encoding="utf-8",
        )
        cfg = MagicMock()
        cfg.skills_enabled = True
        cfg.skills_routing_enabled = True
        cfg.skills_routing_rules_path = str(p)
        mock_router_gs.return_value = cfg
        mock_routing_gs.return_value = cfg
        try:
            clear_routing_rules_cache()
            out = resolve_active_skill_ids(
                ["dfir-log-triage"],
                "case-1",
                case_name="客户勒索事件排查",
                case_meta={},
                user_message="hello",
            )
            assert out == ["dfir-report-checklist", "dfir-log-triage"]
        finally:
            clear_routing_rules_cache()
            p.unlink(missing_ok=True)


class TestSkillStorage:
    def test_sanitize_pack_slug(self):
        from src.skills.storage import sanitize_skill_pack_slug

        assert sanitize_skill_pack_slug("dfir-report-checklist") == "dfir-report-checklist"
        assert sanitize_skill_pack_slug("a b") == "a_b"
        assert sanitize_skill_pack_slug("") is None
