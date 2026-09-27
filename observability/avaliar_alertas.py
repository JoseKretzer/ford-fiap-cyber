"""Avalia as regras de observability/alert_rules.yml sobre a série da simulação
(observability/serie_metricas.json) para validar os limiares:
  - todo ataque simulado deve disparar o alerta do seu playbook;
  - o tráfego normal não deve disparar nenhum alerta (sem falso positivo).

A série tem resolução de 5 min, então cada regra é avaliada na janela equivalente
(5 min = 1 intervalo, 10 min = 2, 15 min = 3, 1 h = 12). As cláusulas `for:` (1-15 min)
não são simuladas nessa resolução.

Uso (a partir de cyber/):  .venv\\Scripts\\python observability\\avaliar_alertas.py
"""
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# alerta -> (descrição do limiar, janela em intervalos, função(valores por intervalo) -> valor, limiar)
ATTACK_TICKS = {
    "ForcaBrutaLogin": {8, 9, 10},
    "SondagemDeAutorizacao": {14, 15, 16},
    "TokensForjadosOuExpirados": {19},
    "TelemetriaRejeitada": {21, 22},
    "AppDesatualizadoEmUso": {4, 5, 6, 7},
}


def load_series() -> list[dict]:
    raw = json.loads((ROOT / "observability" / "serie_metricas.json").read_text(encoding="utf-8"))
    ticks = []
    for row in raw:
        m = defaultdict(float)
        buckets = defaultdict(float)
        score_buckets = defaultdict(float)
        for key, value in row["delta"].items():
            name, labels = key.split("{", 1)
            labels = json.loads("{" + labels)
            if name == "vinshare_auth_login_total":
                m[f"login_{labels['result']}"] += value
            elif name == "vinshare_rate_limited_total":
                m["login_blocked" if labels["scope"].startswith("login") else "api_blocked"] += value
            elif name == "vinshare_http_requests_total":
                m["http_total"] += value
                if labels["status"].startswith("5"):
                    m["http_5xx"] += value
            elif name == "vinshare_authz_denied_total":
                m["authz_denied"] += value
            elif name == "vinshare_auth_token_rejected_total":
                m[f"token_{labels['reason']}"] += value
            elif name == "vinshare_ml_predictions_total":
                m["predictions"] += value
            elif name == "vinshare_ml_churn_score_bucket":
                score_buckets[float(labels["le"])] += value
            elif name == "vinshare_http_request_duration_seconds_bucket":
                buckets[float(labels["le"])] += value
            elif name == "vinshare_iot_messages_total":
                m["iot_" + ("aceita" if labels["result"] == "aceita" else "rejeitada")] += value
            elif name == "vinshare_mobile_requests_total":
                m[f"mobile_{labels['result']}"] += value
        total = buckets.get(float("inf"), 0)
        m["p95_s"] = next((le for le in sorted(buckets) if buckets[le] >= 0.95 * total), 0) if total else 0
        m["score_le_07"] = score_buckets.get(0.7, 0)
        m["score_count"] = score_buckets.get(float("inf"), 0)
        ticks.append(m)
    return ticks


def _window(ticks, i, n, key):
    return sum(ticks[j][key] for j in range(max(0, i - n + 1), i + 1))


RULES = {
    "ForcaBrutaLogin": ("falhas + bloqueios de login > 30 em 5 min",
                        lambda t, i: t[i]["login_failure"] + t[i]["login_blocked"], 30),
    "SondagemDeAutorizacao": ("negações 403 > 5 em 5 min", lambda t, i: t[i]["authz_denied"], 5),
    "TokensForjadosOuExpirados": ("JWT inválidos > 20 em 5 min", lambda t, i: t[i]["token_invalid_token"], 20),
    "ErrosServidor": ("5xx > 2% em 5 min",
                      lambda t, i: t[i]["http_5xx"] / t[i]["http_total"] if t[i]["http_total"] else 0, 0.02),
    "LatenciaAlta": ("p95 > 0,5 s", lambda t, i: t[i]["p95_s"], 0.5),
    "AppDesatualizadoEmUso": ("requisições 426 > 10 em 15 min",
                              lambda t, i: _window(t, i, 3, "mobile_bloqueada"), 10),
    "TelemetriaRejeitada": ("telemetria rejeitada > 10 em 10 min",
                            lambda t, i: _window(t, i, 2, "iot_rejeitada"), 10),
    "DriftScoreChurn": ("> 50% das predições com score > 0,7 em 1 h",
                        lambda t, i: 1 - (_window(t, i, 12, "score_le_07") / _window(t, i, 12, "score_count"))
                        if _window(t, i, 12, "score_count") else 0, 0.5),
    "VolumePredicoesAnomalo": ("predições > 500 em 5 min", lambda t, i: t[i]["predictions"], 500),
}


def evaluate() -> list[dict]:
    ticks = load_series()
    report = []
    for alert, (desc, fn, threshold) in RULES.items():
        values = [fn(ticks, i) for i in range(len(ticks))]
        firing = {i for i, v in enumerate(values) if v > threshold}
        expected = ATTACK_TICKS.get(alert, set())
        # disparo tardio dentro da janela da regra (ex.: 10-15 min) ainda conta como detecção do ataque
        window_slack = {"AppDesatualizadoEmUso": 2, "TelemetriaRejeitada": 1}.get(alert, 0)
        allowed = {t + d for t in expected for d in range(window_slack + 1)}
        report.append({
            "alerta": alert, "limiar": desc, "pico": max(values), "limite": threshold,
            "disparos": sorted(firing),
            "ataque": sorted(expected),
            "detectou": bool(expected) and bool(firing & expected),
            "falsos_positivos": sorted(firing - allowed),
        })
    return report


if __name__ == "__main__":
    for r in evaluate():
        status = ("OK  " if (r["detectou"] or not r["ataque"]) and not r["falsos_positivos"] else "FALHA")
        print(f"{status} {r['alerta']:<27} pico={r['pico']:.3g} limite={r['limite']} "
              f"disparos(min)={[t * 5 for t in r['disparos']]} ataque(min)={[t * 5 for t in r['ataque']]} "
              f"falsos+={[t * 5 for t in r['falsos_positivos']]}")
