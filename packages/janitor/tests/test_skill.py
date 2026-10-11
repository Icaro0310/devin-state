"""Skill/plugin surface contract: the shipped skill exists, has valid
frontmatter, is read-only by text, and the plugin manifest is
self-consistent."""

import json
from pathlib import Path

ADAPTERS = Path(__file__).parents[1] / "adapters"
SKILL = ADAPTERS / "skills" / "devin-janitor" / "SKILL.md"
MANIFEST = ADAPTERS / ".devin-plugin" / "plugin.json"


def _frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---"), "SKILL.md missing frontmatter"
    block = text.split("---", 2)[1]
    out = {}
    for line in block.strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            out[key.strip()] = value.strip()
    return out


def test_skill_exists_with_required_frontmatter():
    assert SKILL.is_file()
    fm = _frontmatter(SKILL)
    assert fm["name"] == "devin-janitor"
    assert fm["description"]


def test_skill_never_exposes_mutation():
    """The read-only contract: the skill must not reference any
    write path — not even to describe it."""
    body = SKILL.read_text(encoding="utf-8").lower()
    assert "read-only" in body
    for banned in ("--apply", "--yes", "--retry", "vacuum", "restore",
                   "install", "export", "pending-file"):
        assert banned not in body


def test_plugin_manifest_self_consistent():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["name"] == "devin-janitor"
    assert (ADAPTERS / "skills" / "devin-janitor" / "SKILL.md").is_file()
    servers = manifest.get("mcpServers", {})
    assert "devin-janitor" in servers
    assert "devin-janitor-mcp" in json.dumps(servers["devin-janitor"])
