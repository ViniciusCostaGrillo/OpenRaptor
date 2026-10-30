# Task 1 Brief: Reestruturação Canônica de Skills e Submódulo Git

## Files
- Create: `skills/` (diretório movido de `.claude/skills/`)
- Modify: `.gitmodules`
- Modify: `core/audit/validate.py`
- Modify: `core/orchestration/agentic_passes.py`
- Modify: `packages/binary_analysis/blamed_lines.py`
- Test: `tests/test_skills_structure.py`

## Global Constraints
- Target OS: Kali Linux / Debian-based x86_64 e arm64.
- Não quebrar caminhos do submódulo Git SecOpsAgentKit.
- Todos os testes devem rodar com pytest e passar.

## Interfaces
- Consumes: Estrutura legada em `.claude/skills/`
- Produces: `skills/` canônica na raiz do projeto com caminhos Python atualizados.

## Instructions
1. Write failing test `tests/test_skills_structure.py`:
```python
from pathlib import Path

def test_skills_canonical_root():
    root = Path(__file__).resolve().parent.parent
    skills_dir = root / "skills"
    assert skills_dir.is_dir(), "skills/ deve existir na raiz"
    assert (skills_dir / "exploitability-validation").is_dir()
    assert (skills_dir / "SecOpsAgentKit").exists()
```
2. Run `pytest tests/test_skills_structure.py -v` (expect FAIL).
3. Move `.claude/skills/` to `skills/` in repo root.
4. Update `.gitmodules` replacing `.claude/skills/SecOpsAgentKit` with `skills/SecOpsAgentKit`.
5. Update hardcoded paths in `core/audit/validate.py`, `core/orchestration/agentic_passes.py`, and `packages/binary_analysis/blamed_lines.py` that reference `.claude/skills/` so they reference `skills/`.
6. Run `pytest tests/test_skills_structure.py -v` (expect PASS).
7. Commit: `git add skills .gitmodules core/ packages/ tests/test_skills_structure.py && git commit -m "refactor: relocate skills to canonical root directory and update references"`.

Report file to write when done: `e:\Raptor Fork\.superpowers\sdd\task-1-report.md`.
