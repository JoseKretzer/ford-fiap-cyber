# Ford VIN Share — Sprint 3: Cybersecurity (DevSecOps)

**FIAP · Challenge Ford 2026 · Desafio 02 — Impulsionando o VIN Share na América do Sul com Soluções Inteligentes**

Entrega da disciplina de Cybersecurity do Challenge Ford 2026. A solução ajuda concessionárias a reter clientes
no pós-venda medindo o **VIN Share** (percentual de veículos Ford que fazem manutenção na rede oficial),
através de um app mobile, uma API REST, telemetria de veículos conectados (IoT) e um modelo de Machine
Learning de previsão de churn.

## Grupo

| Integrante | RM | Turma |
|---|---|---|
| José Antonio Kretzer Rodriguez | RM555523 | 3ESPW |
| Guilherme Machado Moreira | RM557290 | 3ESPV |
| Enzo Almeida Santos Ramos | RM556900 | 3ESPV |
| Gabriel de Mello Silva Fernandes | RM554421 | 3ESPV |

## Documento de entrega

O documento oficial desta Sprint é **[docs/Sprint3_Cybersecurity_Ford_VINShare.docx](docs/Sprint3_Cybersecurity_Ford_VINShare.pdf)**.

Ele é um arquivo único, organizado pelas 4 subetapas do enunciado, e a seção **0.3** liga cada requisito do
enunciado à seção do documento e ao arquivo do repositório que o atende. O restante deste repositório é a
evidência técnica por trás do documento.

| Subetapa | Peso | Onde está |
|---|---|---|
| 1. Pipeline DevSecOps Integrado | 3,0 | [.github/workflows/devsecops.yml](.github/workflows/devsecops.yml), [.gitleaks.toml](.gitleaks.toml), [.semgrep/](.semgrep/), [.trivyignore](.trivyignore), [.github/dependabot.yml](.github/dependabot.yml) |
| 2. Segurança em Código e Infraestrutura | 2,5 | [api/app/](api/app/), [mobile/](mobile/), [iot/](iot/), [api/Dockerfile](api/Dockerfile), [infra/k8s/api.yaml](infra/k8s/api.yaml) |
| 3. Observabilidade, Monitoramento e Resposta | 2,0 | [observability/](observability/) (alertas, dashboard, logs reais, simulador de ataques, avaliador de alertas) |
| 4. Compliance, Riscos e Segurança Contínua | 2,5 | Seção 4 do documento (STRIDE, riscos DevSecOps, ASVS, API/Mobile Top 10, LGPD, checklist) |

As saídas reais das ferramentas de segurança (Gitleaks, Semgrep, Bandit, pip-audit, Trivy, pytest) estão em
[docs/evidencias/](docs/evidencias/).

## Arquitetura da solução

- **App mobile** (Expo/React Native) — consultores e gestores trabalham leads de serviço
- **API REST** (FastAPI) — expõe leads, indicadores de Service Share e predições de churn
- **Telemetria de veículos conectados** (MQTT + serviço de ingestão)
- **Modelo de Machine Learning** — estima a probabilidade de o veículo sair da rede Ford

## Pipeline DevSecOps

O workflow [`devsecops.yml`](.github/workflows/devsecops.yml) roda a cada `push`/`pull request` com 8 etapas:

1. **Secret scanning** (Gitleaks)
2. **SAST** (Semgrep + Bandit)
3. **SCA** (pip-audit, npm audit, Dependency Review)
4. **Testes automatizados** (pytest — API + IoT, 77 testes)
5. **Build + scan de containers/IaC** (Trivy, SBOM, cosign)
6. **Deploy staging** (Azure OIDC)
7. **DAST** (OWASP ZAP)
8. **Deploy produção** (aprovação manual)

Nenhuma etapa é apenas informativa: se um *gate* falha, o merge é bloqueado pela proteção de branch e o
deploy não acontece.

## Como executar (Windows / PowerShell, a partir desta pasta)

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r api\requirements-dev.txt -r iot\requirements.txt cryptography matplotlib python-docx defusedxml semgrep bandit pip-audit

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

> Gitleaks e Trivy são binários. Baixe dos releases oficiais e confira o SHA-256 contra o arquivo
> `*_checksums.txt` do release.

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

## Estrutura do repositório

ford-fiap-cyber/

├── .github/workflows/devsecops.yml pipeline DevSecOps (8 etapas, Actions fixadas por SHA)

├── .github/dependabot.yml SCA contínuo (pip, npm, Docker, compose, Actions)|

├── .gitleaks.toml .semgrep/ .zap/ .trivyignore regras e exceções das ferramentas

├── api/ API FastAPI (app/, tests/, Dockerfile)

├── mobile/ sessão segura + hardening Android (Expo)

├── iot/ broker (TLS/mTLS/ACL/CRL), ingestão, PKI, tests/

├── infra/ docker-compose, k8s/api.yaml, .env.example

├── observability/ Prometheus, Alertmanager, Loki, Alloy, Grafana, simulador

└── docs/ documento Word, figuras, evidências e geradores


## Status do pipeline

O workflow `devsecops` roda a cada push em
[github.com/JoseKretzer/ford-fiap-cyber/actions](https://github.com/JoseKretzer/ford-fiap-cyber/actions).
As etapas 1–5 (secret scanning, SAST, SCA, testes e build/scan) rodam normalmente; as etapas 6–8
(deploy/DAST/produção) ficam como *skipped* até o AKS e os secrets do Azure serem provisionados.
