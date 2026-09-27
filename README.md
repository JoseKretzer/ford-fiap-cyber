# Ford VIN Share: Sprint 3, Cybersecurity (DevSecOps)

Entrega de Cybersecurity do Challenge Ford 2026 (Desafio 02, VIN Share).
O documento para entregar é [docs/Sprint3_Cybersecurity_Ford_VINShare.docx](docs/Sprint3_Cybersecurity_Ford_VINShare.docx).
Ele é um arquivo único, separado pelas 4 subetapas, e a seção 0.3 liga cada requisito do enunciado à seção e ao arquivo que o atende.
O resto do repositório é a evidência técnica.

| Subetapa | Peso | Onde está |
|---|---|---|
| 1. Pipeline DevSecOps Integrado | 3,0 | [.github/workflows/devsecops.yml](.github/workflows/devsecops.yml), [.gitleaks.toml](.gitleaks.toml), [.semgrep/](.semgrep/), [.trivyignore](.trivyignore), [.github/dependabot.yml](.github/dependabot.yml) |
| 2. Segurança em Código e Infraestrutura | 2,5 | [api/app/](api/app/), [mobile/](mobile/), [iot/](iot/), [api/Dockerfile](api/Dockerfile), [infra/k8s/api.yaml](infra/k8s/api.yaml) |
| 3. Observabilidade, Monitoramento e Resposta | 2,0 | [observability/](observability/) (alertas, dashboard, logs reais, simulador, avaliador de alertas) |
| 4. Compliance, Riscos e Segurança Contínua | 2,5 | Seção 4 do documento (STRIDE, riscos DevSecOps, ASVS, API/Mobile Top 10, LGPD, checklist) |

Saídas reais das ferramentas (Gitleaks, Semgrep, Bandit, pip-audit, Trivy, pytest): [docs/evidencias/](docs/evidencias/).

## Como executar (Windows / PowerShell, a partir desta pasta)

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r api\requirements-dev.txt -r iot\requirements.txt cryptography matplotlib python-docx semgrep bandit pip-audit

# Testes: API (49) e IoT (28, inclui handshake mTLS real)
cd api; ..\.venv\Scripts\python -m pytest -v; cd ..\iot; ..\.venv\Scripts\python -m pytest -v; cd ..

# Ferramentas do pipeline
.venv\Scripts\python .semgrep\verificar_regras.py
.venv\Scripts\semgrep scan --config .semgrep/vinshare-rules.yml --config p/owasp-top-ten --exclude .semgrep api iot mobile
.venv\Scripts\bandit -r api/app iot -x iot/tests -ll -ii
.venv\Scripts\pip-audit -r api\requirements.txt -r iot\requirements.txt

# Simulação de ataques -> logs e métricas reais -> validação dos alertas
.venv\Scripts\python observability\simular_trafego.py
.venv\Scripts\python observability\avaliar_alertas.py

# Figuras e documento Word
.venv\Scripts\python docs\gerar_figuras.py
.venv\Scripts\python docs\gerar_documento.py
```

Gitleaks e Trivy são binários. Baixe dos releases oficiais e confira o SHA-256 contra o arquivo `*_checksums.txt` do release.

### Stack local completa (Docker)

Pré-requisito: `openssl` no PATH (vem com o Git for Windows).

```powershell
cd iot; .\gerar_certificados.ps1; cd ..\infra
copy .env.example .env
# Gerar segredos e colar no .env:
python -c "import secrets,base64;print('JWT_SECRET='+secrets.token_urlsafe(48));print('DATA_KEY_B64='+base64.b64encode(secrets.token_bytes(32)).decode());print('INDEX_KEY_B64='+base64.b64encode(secrets.token_bytes(32)).decode());print('DEMO_PASSWORD='+secrets.token_urlsafe(18))"
python -c "import secrets;print(secrets.token_urlsafe(24))" > grafana_admin.txt
# URLs de webhook do Teams (Workflows) para o Alertmanager; qualquer URL serve para testar localmente
"https://example.invalid/webhook" > teams_webhook_time.txt; "https://example.invalid/webhook" > teams_webhook_seguranca.txt
docker compose up --build
```

- API: http://localhost:8000/docs (Swagger só fora de produção)
- Grafana: http://localhost:3000 (usuário `admin`, senha em `grafana_admin.txt`), pasta *VIN Share*
- Prometheus: http://localhost:9090 · Alertmanager: http://localhost:9093

Usuários de demonstração (senha = `DEMO_PASSWORD`): `consultor.sp01`, `gestor.sp01`, `consultor.rj02`, `admin.ford`.
Revogar um dispositivo IoT (playbook PB-04): `iot\gerar_certificados.ps1 -Revogar veh-XXXXXXXXXXXXXXXX`.

## Antes de entregar

1. Preencher a capa do documento (grupo, integrantes/RM, turma, link do repositório).
2. Publicar esta pasta no GitHub, com um commit por correção da tabela 2.7 do documento. Colar os links dos commits e o print da aba *Actions* (workflow `devsecops` verde) na seção 2.7.
3. Subir a stack com Docker e colar o print do dashboard do Grafana na seção 3.3.
4. Nas configurações do repositório: proteção de branch em `main` (exigir os checks e 1 revisão, inclusive para admins) e os environments `staging`/`production` (este com revisor obrigatório).
