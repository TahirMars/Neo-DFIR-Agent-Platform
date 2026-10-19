#!/usr/bin/env python3
"""
将 CyberSkills 中 analyzing-* / hunting-* 技能同步到 backend/src/skills/builtin（取证与威胁猎捕向）。
排除恶意样本逆向/沙箱/专用恶意文档分析类技能；为每条技能写入 neo_agents 供子智能体过滤注入。

用法（仓库根目录）: uv run python backend/scripts/sync_forensic_hunting_builtin_skills.py
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

import yaml

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL | re.MULTILINE)

# 恶意样本分析 / 逆向 / 沙箱等（暂不转化）
MALWARE_SAMPLE_EXCLUDE: frozenset[str] = frozenset({
    "analyzing-android-malware-with-apktool",
    "analyzing-bootkit-and-rootkit-samples",
    "analyzing-ethereum-smart-contract-vulnerabilities",
    "analyzing-golang-malware-with-ghidra",
    "analyzing-heap-spray-exploitation",
    "analyzing-ios-app-security-with-objection",
    "analyzing-linux-elf-malware",
    "analyzing-macro-malware-in-office-documents",
    "analyzing-malicious-pdf-with-peepdf",
    "analyzing-malware-behavior-with-cuckoo-sandbox",
    "analyzing-malware-family-relationships-with-malpedia",
    "analyzing-malware-persistence-with-autoruns",
    "analyzing-malware-sandbox-evasion-techniques",
    "analyzing-network-covert-channels-in-malware",
    "analyzing-network-traffic-of-malware",
    "analyzing-packed-malware-with-upx-unpacker",
    "analyzing-pdf-malware-with-pdfid",
    "analyzing-ransomware-encryption-mechanisms",
    "analyzing-supply-chain-malware-artifacts",
})

# 报告整合 / MITRE / 归因类：额外挂载到 report
FORENSIC_REPORT_CHAT: frozenset[str] = frozenset({
    "analyzing-cyber-kill-chain",
    "analyzing-threat-actor-ttps-with-mitre-attack",
    "analyzing-threat-actor-ttps-with-mitre-navigator",
    "analyzing-apt-group-with-mitre-navigator",
    "analyzing-campaign-attribution-evidence",
    "analyzing-indicators-of-compromise",
    "analyzing-threat-intelligence-feeds",
    "analyzing-threat-landscape-with-misp",
    "hunting-advanced-persistent-threats",
})


def _neo_agents_for(slug: str) -> list[str]:
    if slug in FORENSIC_REPORT_CHAT:
        return ["forensic", "report", "general_chat"]
    return ["forensic", "general_chat"]


def main() -> None:
    neo_root = Path(__file__).resolve().parents[2]
    cyber_skills = neo_root / "CyberSkills" / "skills"
    builtin_root = neo_root / "backend" / "src" / "skills" / "builtin"
    if not cyber_skills.is_dir():
        raise SystemExit(f"未找到 CyberSkills 目录: {cyber_skills}")

    copied = 0
    skipped = 0
    for child in sorted(cyber_skills.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        if not (name.startswith("analyzing-") or name.startswith("hunting-")):
            continue
        if name in MALWARE_SAMPLE_EXCLUDE:
            skipped += 1
            continue
        src = child / "SKILL.md"
        if not src.is_file():
            skipped += 1
            continue

        raw = src.read_text(encoding="utf-8")
        m = _FRONTMATTER_RE.match(raw.strip())
        if not m:
            skipped += 1
            continue
        try:
            fm = yaml.safe_load(m.group(1)) or {}
        except yaml.YAMLError:
            skipped += 1
            continue
        if not isinstance(fm, dict):
            skipped += 1
            continue

        body = m.group(2).lstrip("\n")
        fm["id"] = str(fm.get("id") or name).strip()
        fm["neo_agents"] = _neo_agents_for(name)

        fm_yaml = yaml.dump(
            fm,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        ).rstrip() + "\n"
        out = f"---\n{fm_yaml}---\n\n{body}"

        dest_dir = builtin_root / name
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "SKILL.md").write_text(out, encoding="utf-8")

        # 可选：复制 references/、scripts/ 供人机阅读（Neo 运行时仅解析 SKILL.md）
        for sub in ("references", "scripts"):
            sub_src = child / sub
            if sub_src.is_dir():
                dest_sub = dest_dir / sub
                if dest_sub.exists():
                    shutil.rmtree(dest_sub)
                shutil.copytree(sub_src, dest_sub)

        copied += 1

    print(f"sync 完成: 写入 {copied} 个技能包到 {builtin_root}，跳过 {skipped} 项。")


if __name__ == "__main__":
    main()
