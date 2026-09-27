# syntax=docker/dockerfile:1
# Imagem da API VIN Share - build multi-stage com boas práticas de segurança.
# Verificada no pipeline por: Trivy (vulnerabilidades + misconfig) e hadolint.

# ---------- estágio 1: instala dependências (tem pip/compilador, NÃO vai para produção)
FROM python:3.13-slim-trixie AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------- estágio 2: runtime mínimo
FROM python:3.13-slim-trixie
LABEL org.opencontainers.image.source="https://github.com/ORG/ford-vinshare" \
      org.opencontainers.image.description="Ford VIN Share API"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=prod

# Atualiza pacotes do SO (corrige CVEs da base) e cria usuário sem privilégios
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

# O runtime não precisa de pip: remover tira da imagem as CVEs dele e uma ferramenta útil para um invasor
RUN python -m pip uninstall -y pip && rm -rf /root/.cache

COPY --from=builder /install /usr/local
WORKDIR /srv
COPY --chown=root:root --chmod=0555 app ./app

# Nenhum segredo na imagem: JWT_SECRET, DATA_KEY_B64 e INDEX_KEY_B64 são injetados
# em runtime pelo orquestrador (Kubernetes Secret / Azure Key Vault).
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "app.main:get_app", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "10.0.0.0/8", "--no-server-header"]
