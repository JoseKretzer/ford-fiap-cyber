"""Valida as regras Semgrep do projeto contra os casos anotados (equivalente ao `semgrep --test`,
que não funciona no Windows). Cada `# ruleid: X` exige achado X na linha seguinte; cada
`# ok: X` exige ausência de X na linha seguinte.

Uso (a partir de cyber/):  .venv\\Scripts\\python .semgrep\\verificar_regras.py
"""
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
CASES = [HERE / "vinshare-rules.py", HERE / "vinshare-rules.ts"]
SEMGREP = Path(sys.executable).with_name("semgrep.exe" if sys.platform == "win32" else "semgrep")

result = subprocess.run(
    [str(SEMGREP), "scan", "--config", str(HERE / "vinshare-rules.yml"), "--json", "--metrics=off",
     "--disable-version-check", "--no-git-ignore", *map(str, CASES)],
    capture_output=True, text=True, encoding="utf-8", env={**__import__("os").environ, "PYTHONUTF8": "1"},
)
data = json.loads(result.stdout)
found = {(Path(r["path"]).name, r["start"]["line"], r["check_id"].split(".")[-1]) for r in data["results"]}

expected, forbidden = set(), set()
for case in CASES:
    for n, line in enumerate(case.read_text(encoding="utf-8").splitlines(), start=1):
        m = re.search(r"(?:#|//)\s*(ruleid|ok):\s*([\w-]+)", line)
        if m:
            (expected if m.group(1) == "ruleid" else forbidden).add((case.name, n + 1, m.group(2)))

missing = expected - found
false_pos = forbidden & found
print(f"Regras: {len({r for *_, r in expected})} | casos positivos: {len(expected)} | casos negativos: {len(forbidden)}")
print(f"Detectados corretamente: {len(expected & found)}/{len(expected)} | falsos positivos: {len(false_pos)}")
for item in sorted(missing):
    print("  NÃO DETECTADO:", item)
for item in sorted(false_pos):
    print("  FALSO POSITIVO:", item)
sys.exit(1 if missing or false_pos else 0)
