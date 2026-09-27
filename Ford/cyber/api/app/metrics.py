"""Métricas Prometheus da API (coletadas pelo Prometheus e exibidas no Grafana).

Cada métrica de segurança alimenta uma regra de alerta em observability/alert_rules.yml.
"""
from prometheus_client import CollectorRegistry, Counter, Histogram


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter("vinshare_http_requests_total", "Requisições HTTP",
                                ["method", "route", "status"], registry=self.registry)
        self.latency = Histogram("vinshare_http_request_duration_seconds", "Latência HTTP",
                                 ["route"], registry=self.registry,
                                 buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5))
        self.login = Counter("vinshare_auth_login_total", "Tentativas de login",
                             ["result"], registry=self.registry)
        self.token_rejected = Counter("vinshare_auth_token_rejected_total", "Tokens rejeitados",
                                      ["reason"], registry=self.registry)
        self.authz_denied = Counter("vinshare_authz_denied_total", "Acessos negados (403)",
                                    ["permission"], registry=self.registry)
        self.rate_limited = Counter("vinshare_rate_limited_total", "Requisições bloqueadas por rate limit",
                                    ["scope"], registry=self.registry)
        self.client_requests = Counter("vinshare_mobile_requests_total",
                                       "Requisições do app mobile por versão (versões inválidas = 'outra')",
                                       ["app_version", "result"], registry=self.registry)
        self.predictions = Counter("vinshare_ml_predictions_total", "Predições de churn servidas",
                                   ["risk"], registry=self.registry)
        self.prediction_score = Histogram("vinshare_ml_churn_score", "Distribuição do score (detecção de drift)",
                                          registry=self.registry,
                                          buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0))
