from pathlib import Path

EXPECTED_AAS_SKILLS = [
    "ethical-hacking-methodology",
    "burp-suite-testing",
    "top-web-vulnerabilities",
    "api-security-testing",
    "linux-privilege-escalation",
    "cloud-penetration-testing",
    "security-auditor",
    "vulnerability-scanner",
    "sast-configuration",
    "web-security-testing",
    "threat-modeling-expert",
    "skill-security-audit"
]

def test_aas_security_engineer_skills_exist():
    root = Path(__file__).resolve().parent.parent
    skills_root = root / "skills"
    opencode_skills = root / ".opencode" / "skills"
    
    assert skills_root.is_dir(), "skills/ deve existir"
    assert opencode_skills.is_dir(), ".opencode/skills/ deve existir"
    
    for skill in EXPECTED_AAS_SKILLS:
        skill_file = skills_root / skill / "SKILL.md"
        assert skill_file.is_file(), f"Skill {skill}/SKILL.md deve existir em skills/"
        content = skill_file.read_text(encoding="utf-8")
        assert content.startswith("---"), f"{skill}/SKILL.md deve ter frontmatter YAML"
        
        opencode_skill_file = opencode_skills / skill / "SKILL.md"
        assert opencode_skill_file.is_file(), f"Skill {skill}/SKILL.md deve existir em .opencode/skills/"
