"""Gera as figuras do documento de Cybersecurity (docs/img/*.png).

- painel_monitoramento.png : painel montado com as métricas REAIS da simulação
  (observability/serie_metricas.json), com os mesmos painéis do dashboard Grafana.
- arquitetura_seguranca.png, pipeline_devsecops.png, resposta_incidentes.png : diagramas.
"""
import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "docs" / "img"
IMG.mkdir(parents=True, exist_ok=True)

# Paleta de referência (modo claro)
SURFACE, INK, INK2, MUTED = "#fcfcfb", "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"
SEQ = {"baixo": "#86b6ef", "medio": "#2a78d6", "alto": "#114788"}
CRIT = "#cf3939"
FORD = "#133879"

plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans"],
    "font.size": 9,
    "axes.edgecolor": AXIS,
    "axes.labelcolor": INK2,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.titlecolor": INK,
    "axes.titlesize": 10,
    "axes.titleweight": "semibold",
    "axes.titlelocation": "left",
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
})


# ------------------------------------------------------------------ painel de monitoramento
def load_series():
    raw = json.loads((ROOT / "observability" / "serie_metricas.json").read_text(encoding="utf-8"))
    ticks = [r["tick"] for r in raw]
    out = defaultdict(lambda: [0.0] * len(ticks))
    buckets: list[dict[float, float]] = [{} for _ in ticks]
    for i, row in enumerate(raw):
        for key, value in row["delta"].items():
            name, labels = key.split("{", 1)
            labels = json.loads("{" + labels)
            if name == "vinshare_http_request_duration_seconds_bucket":
                le = float(labels["le"])
                buckets[i][le] = buckets[i].get(le, 0) + value
                continue
            if name == "vinshare_auth_login_total":
                out[f"login_{labels['result']}"][i] += value
            elif name == "vinshare_rate_limited_total" and labels["scope"].startswith("login"):
                out["login_blocked"][i] += value
            elif name == "vinshare_http_requests_total":
                s = labels["status"]
                cls = "429" if s == "429" else s[0] + "xx"
                out[f"http_{cls}"][i] += value
            elif name == "vinshare_authz_denied_total":
                out["authz_denied"][i] += value
            elif name == "vinshare_auth_token_rejected_total":
                out["token_rejected"][i] += value
            elif name == "vinshare_ml_predictions_total":
                out[f"pred_{labels['risk']}"][i] += value
            elif name == "vinshare_iot_messages_total":
                out["iot_" + ("aceita" if labels["result"] == "aceita" else "rejeitada")][i] += value
            elif name == "vinshare_mobile_requests_total":
                out[f"mobile_{labels['result']}"][i] += value
    p95 = []
    for i in range(len(ticks)):
        b = buckets[i]  # buckets do histograma são cumulativos: p95 = menor "le" com >= 95%
        total = b.get(float("inf"), 0)
        if not total:
            p95.append(0)
            continue
        target = 0.95 * total
        p95.append(next(le for le in sorted(b) if b[le] >= target) * 1000)
    minutes = [t * 5 for t in ticks]
    return minutes, out, p95


def style(ax, ylabel=None):
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=0)
    ax.set_xlim(-3, 118)
    ax.set_xticks(range(0, 120, 20))
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=8)


def attack_window(ax, start, end, label):
    ax.axvspan(start * 5 - 2.5, end * 5 + 2.5, color="#f0efec", zorder=0)
    ax.text((start + end) / 2 * 5, ax.get_ylim()[1] * 0.97, label, ha="center", va="top",
            fontsize=7.5, color=INK2)


def direct_label(ax, x, y, text, color):
    ax.annotate(text, (x, y), xytext=(4, 0), textcoords="offset points", fontsize=8,
                color=INK2, va="center")
    ax.plot([x], [y], "o", color=color, markersize=4)


def painel():
    minutes, s, p95 = load_series()
    fig, axes = plt.subplots(3, 3, figsize=(13, 9.6))
    fig.suptitle("VIN Share · Segurança e Operação  (simulação de 2 h, intervalos de 5 min)",
                 x=0.012, ha="left", fontsize=12, fontweight="semibold", color=INK)

    ax = axes[0][0]
    ax.plot(minutes, s["login_success"], color=S1, lw=2, label="sucesso")
    ax.plot(minutes, s["login_failure"], color=S2, lw=2, label="falha (senha errada)")
    ax.plot(minutes, s["login_blocked"], color=S3, lw=2, label="bloqueado (rate limit)")
    ax.set_title("Tentativas de login")
    style(ax, "tentativas / 5 min")
    ax.set_ylim(0, max(s["login_blocked"]) * 1.25)
    attack_window(ax, 8, 10, "força bruta\n(PB-01)")
    ax.legend(frameon=False, fontsize=7.5, loc="center right", labelcolor=INK2)

    ax = axes[0][1]
    ax.plot(minutes, s["http_2xx"], color=S1, lw=2, label="2xx")
    ax.plot(minutes, s["http_4xx"], color=S2, lw=2, label="4xx (401/403/404/422/426)")
    ax.set_title("Requisições por status HTTP (429: ver painel de login)")
    style(ax, "requisições / 5 min")
    ax.set_ylim(0, max(s["http_2xx"] + s["http_4xx"]) * 1.35)
    ax.legend(frameon=False, fontsize=7.5, loc="upper left", labelcolor=INK2, ncol=2)

    ax = axes[0][2]
    ax.plot(minutes, p95, color=S1, lw=2)
    ax.axhline(500, color=CRIT, lw=1, ls=(0, (4, 3)))
    ax.text(116, 500, "alerta: 500 ms", ha="right", va="bottom", fontsize=7.5, color=INK2)
    ax.set_title("Latência p95 da API")
    style(ax, "ms")
    ax.set_ylim(0, 600)

    ax = axes[1][0]
    ax.bar(minutes, s["authz_denied"], width=3.2, color=S1)
    ax.set_title("Acessos negados (403 e escopo de concessionária)")
    style(ax, "negações / 5 min")
    ax.set_ylim(0, max(s["authz_denied"]) * 1.45 + 1)
    attack_window(ax, 14, 16, "sondagem BOLA\n(PB-02)")

    ax = axes[1][1]
    ax.bar(minutes, s["token_rejected"], width=3.2, color=S1)
    ax.set_title("JWT rejeitados (inválido / expirado)")
    style(ax, "tokens / 5 min")
    ax.set_ylim(0, max(s["token_rejected"]) * 1.45 + 1)
    attack_window(ax, 19, 19, "token forjado\n(PB-03)")

    ax = axes[1][2]
    bottom = [0.0] * len(minutes)
    for risk in ("baixo", "medio", "alto"):
        vals = s[f"pred_{risk}"]
        ax.bar(minutes, vals, width=3.2, bottom=bottom, color=SEQ[risk], label=risk,
               edgecolor=SURFACE, linewidth=1)
        bottom = [a + b for a, b in zip(bottom, vals)]
    ax.set_title("Predições de churn por faixa de risco (ML)")
    style(ax, "predições / 5 min")
    ax.set_ylim(0, max(bottom) * 1.3)
    ax.legend(frameon=False, fontsize=7.5, loc="upper right", ncol=3, labelcolor=INK2)

    ax = axes[2][0]
    ax.plot(minutes, s["iot_aceita"], color=S1, lw=2, label="aceitas")
    ax.plot(minutes, s["iot_rejeitada"], color=S2, lw=2, label="rejeitadas")
    ax.set_title("Telemetria IoT (ingestão)")
    style(ax, "mensagens / 5 min")
    ax.set_ylim(0, max(s["iot_aceita"]) * 1.35)
    attack_window(ax, 21, 22, "replay +\nodômetro (PB-04)")
    ax.legend(frameon=False, fontsize=7.5, loc="center left", labelcolor=INK2)

    ax = axes[2][1]
    ax.bar(minutes, s["mobile_aceita"], width=3.2, color=S1, label="versão suportada")
    ax.bar(minutes, s["mobile_bloqueada"], width=3.2, bottom=s["mobile_aceita"], color=S2,
           label="bloqueada (426)", edgecolor=SURFACE, linewidth=1)
    ax.set_title("App mobile: requisições por versão")
    style(ax, "requisições / 5 min")
    ax.set_ylim(0, max(a + b for a, b in zip(s["mobile_aceita"], s["mobile_bloqueada"])) * 1.35)
    ax.legend(frameon=False, fontsize=7.5, loc="upper right", ncol=2, labelcolor=INK2)

    # Linha do tempo: quando cada regra de alerta dispararia (observability/avaliar_alertas.py)
    import sys
    sys.path.insert(0, str(ROOT / "observability"))
    from avaliar_alertas import evaluate
    report = [r for r in evaluate() if r["disparos"]]
    ax = axes[2][2]
    for row, r in enumerate(reversed(report)):
        for t in r["ataque"]:
            ax.add_patch(plt.Rectangle((t * 5 - 2.5, row - 0.4), 5, 0.8, color="#f0efec", zorder=0))
        ax.scatter([t * 5 for t in r["disparos"]], [row] * len(r["disparos"]), marker="s", s=46,
                   color=CRIT, zorder=3)
    ax.set_yticks(range(len(report)), [r["alerta"] for r in reversed(report)], fontsize=7.2)
    ax.set_title("Alertas que disparariam (cinza = janela do ataque)")
    style(ax)
    ax.grid(axis="y", visible=False)
    ax.set_ylim(-0.7, len(report) - 0.3)

    for ax in axes[2]:
        ax.set_xlabel("minutos desde o início", fontsize=8)
    fig.tight_layout(rect=(0, 0, 1, 0.965))
    fig.savefig(IMG / "painel_monitoramento.png", dpi=170)
    plt.close(fig)


# ------------------------------------------------------------------ diagramas
def box(ax, x, y, w, h, title, lines=(), fill="#ffffff", edge=FORD, title_color=FORD, fs=9):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                fc=fill, ec=edge, lw=1.3))
    ax.text(x + w / 2, y + h - 0.22, title, ha="center", va="top", fontsize=fs,
            fontweight="bold", color=title_color)
    for i, line in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.62 - i * 0.3, line, ha="center", va="top", fontsize=7.4, color=INK2)


def arrow(ax, x1, y1, x2, y2, label=None, color=INK2, both=False, lx=0, ly=0.12, style="-|>"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="<|-|>" if both else style,
                                 mutation_scale=11, color=color, lw=1.2))
    if label:
        ax.text((x1 + x2) / 2 + lx, (y1 + y2) / 2 + ly, label, ha="center", va="bottom",
                fontsize=7, color=INK, bbox=dict(fc=SURFACE, ec="none", pad=0.6))


def zone(ax, x, y, w, h, label):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.2",
                                fc="none", ec=AXIS, lw=1, ls=(0, (5, 3))))
    ax.text(x + 0.15, y + h - 0.12, label, ha="left", va="top", fontsize=7.5, color=MUTED, style="italic")


def arquitetura():
    fig, ax = plt.subplots(figsize=(13, 7.4))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 11.4)
    ax.axis("off")
    ax.text(0.1, 11.2, "Arquitetura de segurança - Ford VIN Share", fontsize=13, fontweight="bold",
            color=INK, va="top")

    zone(ax, 0.1, 5.6, 3.9, 5.0, "Zona não confiável (internet)")
    zone(ax, 4.5, 0.4, 15.3, 10.2, "Azure - VNet privada / AKS (namespace vinshare)")

    box(ax, 0.4, 8.2, 3.3, 2.0, "App mobile (Expo)",
        ["Consultor / Gestor / Admin", "JWT no SecureStore", "sem HTTP em texto claro"])
    box(ax, 0.4, 5.9, 3.3, 2.0, "Veículo conectado",
        ["módulo telemático", "certificado X.509 próprio", "ID = pseudônimo do VIN"])

    box(ax, 5.0, 8.2, 3.3, 2.0, "Ingress NGINX",
        ["TLS 1.2/1.3 · HSTS", "rate limit 20 rps", "body máx. 64 KB"])
    box(ax, 9.3, 7.4, 4.2, 2.8, "API VIN Share (FastAPI)",
        ["1 valida JWT (HS256, exp 15 min)", "2 RBAC + escopo concessionária",
         "3 validação allow-list (Pydantic)", "4 cifra AES-256-GCM de PII", "5 logs JSON + métricas"],
        fill="#eef4fc")
    box(ax, 5.0, 5.9, 3.3, 2.0, "Broker MQTT",
        ["porta 8883 · mTLS", "ACL por dispositivo", "CRL de revogados"])
    box(ax, 9.3, 1.4, 4.2, 2.0, "Serviço de ingestão",
        ["valida esquema e timestamp", "anti-replay (msg_id)", "só leitura no broker"])
    box(ax, 14.5, 4.8, 4.9, 2.3, "PostgreSQL (privado)",
        ["TDE (disco) + PII cifrada por campo", "índice cego HMAC para CPF",
         "backup diário cifrado"])
    box(ax, 14.5, 8.0, 4.9, 2.2, "Azure Key Vault",
        ["JWT_SECRET · DATA_KEY · INDEX_KEY", "rotação 90 dias", "acesso via identidade gerenciada"])
    box(ax, 9.3, 4.4, 4.2, 2.0, "Modelo de churn (ML)",
        ["artefato JSON (sem pickle)", "SHA-256 verificado no load", "entradas com faixas"])
    box(ax, 14.5, 0.7, 4.9, 3.4, "Observabilidade",
        ["Prometheus (métricas)", "Loki (logs JSON)", "Grafana (painéis)",
         "Alertmanager -> Teams / plantão", "retenção de auditoria: 1 ano"], fill="#f5f5f2")
    box(ax, 5.0, 1.0, 3.3, 2.6, "CI/CD GitHub Actions",
        ["Gitleaks · Semgrep · pip-audit", "Trivy · ZAP · cosign", "deploy só de imagem", "assinada (por digest)"],
        fill="#f5f5f2")

    arrow(ax, 3.7, 9.2, 5.0, 9.2, "HTTPS + Bearer JWT")
    arrow(ax, 8.3, 9.2, 9.3, 9.2)
    arrow(ax, 3.7, 6.9, 5.0, 6.9, "MQTT/TLS mTLS")
    arrow(ax, 7.6, 5.9, 9.3, 2.9, "assina tópico", lx=-0.75, ly=-0.1)
    arrow(ax, 14.5, 9.2, 13.5, 9.2, "segredos")
    arrow(ax, 13.5, 7.7, 14.5, 6.5, "SQL/TLS", lx=0.25, ly=0.05)
    arrow(ax, 13.5, 3.0, 14.5, 5.1, "grava", lx=-0.05, ly=0.05)
    arrow(ax, 11.4, 7.4, 11.4, 6.4, "")
    ax.text(11.5, 6.8, "inferência (em processo)", fontsize=7, color=INK, ha="left", va="center")
    arrow(ax, 13.5, 2.0, 14.5, 2.0, "métricas / logs", ly=0.08)

    fig.tight_layout()
    fig.savefig(IMG / "arquitetura_seguranca.png", dpi=170)
    plt.close(fig)


def pipeline():
    import defusedxml.ElementTree as ET  # parser seguro contra XXE (Semgrep use-defused-xml-parse)
    n_tests = sum(int((ET.parse(ROOT / "docs" / "evidencias" / f).getroot().find("testsuite")
                       or ET.parse(ROOT / "docs" / "evidencias" / f).getroot()).get("tests"))
                  for f in ("pytest-report.xml", "pytest-iot-report.xml"))
    stages = [
        ("1 Secret scan", "Gitleaks 8.30", "histórico completo\n+ 4 regras próprias", S1),
        ("2 SAST", "Semgrep + Bandit", "OWASP + 7 regras\ndo projeto", S1),
        ("3 SCA", "pip-audit · npm audit\nDependency Review", "CVE e licenças", S1),
        ("4 Testes", f"pytest ({n_tests} testes\nAPI + IoT)", "authN, authZ, cripto,\nanti-replay, mTLS", S1),
        ("5 Build + scan", "Trivy imagens + IaC\nSBOM CycloneDX", "cosign (assinatura)\nhash do modelo ML", S2),
        ("6 Staging", "deploy por digest\nOIDC no Azure", "sem credencial fixa", S2),
        ("7 DAST", "OWASP ZAP\nbaseline", "headers, TLS,\nexposição", S2),
        ("8 Produção", "aprovação manual\nverifica assinatura", "rollback por digest", S3),
    ]
    fig, ax = plt.subplots(figsize=(14, 3.7))
    ax.set_xlim(0, 32)
    ax.set_ylim(0.4, 7.0)
    ax.axis("off")
    ax.text(0.1, 6.95,"Pipeline DevSecOps - GitHub Actions (.github/workflows/devsecops.yml)",
            fontsize=12.5, fontweight="bold", color=INK, va="top")
    w, gap, y = 3.55, 0.47, 2.2
    for i, (title, tool, note, color) in enumerate(stages):
        x = 0.2 + i * (w + gap)
        ax.add_patch(FancyBboxPatch((x, y), w, 3.9, boxstyle="round,pad=0.02,rounding_size=0.15",
                                    fc="#ffffff", ec=color, lw=1.6))
        ax.add_patch(FancyBboxPatch((x, y + 3.1), w, 0.8, boxstyle="round,pad=0.02,rounding_size=0.15",
                                    fc=color, ec=color, lw=1.6))
        ax.text(x + w / 2, y + 3.5, title, ha="center", va="center", fontsize=9, fontweight="bold",
                color="#ffffff")
        ax.text(x + w / 2, y + 2.55, tool, ha="center", va="top", fontsize=8, color=INK)
        ax.text(x + w / 2, y + 1.15, note, ha="center", va="top", fontsize=7.3, color=INK2)
        if i < len(stages) - 1:
            arrow(ax, x + w + 0.02, y + 1.95, x + w + gap - 0.02, y + 1.95)
    ax.text(0.2, 1.45, "Azul: todo push e PR (gates bloqueiam o merge)     Laranja: só na branch main     "
            "Verde: produção com aprovação de revisor", fontsize=8, color=INK2)
    ax.text(0.2, 0.75, "Também agendado toda segunda às 06:00 UTC (CVEs novas em código parado) · "
            "Dependabot abre PRs semanais (pip, npm, Docker, Actions)", fontsize=8, color=INK2)
    fig.tight_layout()
    fig.savefig(IMG / "pipeline_devsecops.png", dpi=170)
    plt.close(fig)


def resposta():
    steps = [
        ("Detecção", ["alerta Prometheus", "(ex.: ForcaBrutaLogin)", "ou relato / SOC"]),
        ("Análise", ["logs por request_id", "no Loki; escopo,", "severidade P1-P4"]),
        ("Contenção", ["bloquear IP / usuário,", "revogar tokens,", "revogar certificado IoT"]),
        ("Erradicação", ["corrigir causa raiz,", "rotacionar segredos,", "novo deploy pelo pipeline"]),
        ("Recuperação", ["restaurar serviço/backup,", "monitoramento reforçado", "por 72 h"]),
        ("Lições aprendidas", ["post-mortem em 5 dias", "nova regra Semgrep /", "novo alerta / teste"]),
    ]
    fig, ax = plt.subplots(figsize=(13, 3.3))
    ax.set_xlim(0, 26)
    ax.set_ylim(0.3, 6.1)
    ax.axis("off")
    ax.text(0.1, 6.05, "Fluxo de resposta a incidentes (NIST SP 800-61)", fontsize=12.5,
            fontweight="bold", color=INK, va="top")
    w, gap, y = 3.7, 0.6, 2.6
    for i, (title, lines) in enumerate(steps):
        x = 0.2 + i * (w + gap)
        color = CRIT if i == 2 else FORD
        box(ax, x, y, w, 2.2, title, lines, edge=color, title_color=color, fs=10)
        if i < len(steps) - 1:
            arrow(ax, x + w + 0.03, y + 1.1, x + w + gap - 0.03, y + 1.1)
    ax.add_patch(FancyArrowPatch((0.2 + 5 * (w + gap) + w / 2, y - 0.05), (0.2 + w / 2, y - 0.05),
                                 connectionstyle="arc3,rad=-0.1", arrowstyle="-|>",
                                 mutation_scale=11, color=MUTED, lw=1.1, ls=(0, (4, 3))))
    ax.text(13, 1.05, "melhoria contínua: cada incidente vira controle automatizado no pipeline",
            ha="center", fontsize=8, color=INK2, bbox=dict(fc=SURFACE, ec="none", pad=1))
    ax.text(0.2 + 2 * (w + gap) + w / 2, y + 2.45,"LGPD: se envolver dado pessoal, avaliar comunicação à ANPD",
            ha="center", fontsize=7.5, color=CRIT)
    fig.tight_layout()
    fig.savefig(IMG / "resposta_incidentes.png", dpi=170)
    plt.close(fig)


if __name__ == "__main__":
    painel()
    arquitetura()
    pipeline()
    resposta()
    print("Figuras geradas em", IMG)
