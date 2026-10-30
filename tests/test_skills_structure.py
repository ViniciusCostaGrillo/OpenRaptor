from pathlib import Path

def test_skills_canonical_root():
    root = Path(__file__).resolve().parent.parent
    skills_dir = root / "skills"
    assert skills_dir.is_dir(), "skills/ deve existir na raiz"
    assert (skills_dir / "exploitability-validation").is_dir()
    assert (skills_dir / "SecOpsAgentKit").exists()
