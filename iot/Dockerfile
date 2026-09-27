# syntax=docker/dockerfile:1
# Serviço de ingestão de telemetria (mesmas práticas da imagem da API)
FROM python:3.13-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
WORKDIR /srv
COPY requirements.txt .
# Depois de instalar as dependências, remove o pip: o runtime não precisa dele (menos CVEs e superfície)
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m pip uninstall -y pip && rm -rf /root/.cache
COPY --chown=root:root --chmod=0444 ingestion.py .
USER 10001:10001
EXPOSE 9101
# Certificado do serviço montado em runtime (volume somente leitura), nunca copiado para a imagem
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9101/metrics', timeout=2).status == 200 else 1)"]
CMD ["python", "ingestion.py"]
