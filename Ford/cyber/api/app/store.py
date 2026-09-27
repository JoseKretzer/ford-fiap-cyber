"""Repositório em memória com dados SINTÉTICOS (nenhum dado real de cliente).

Os campos pessoais (CPF, telefone) são gravados já cifrados com AES-256-GCM.
Em produção a mesma camada grava no Azure SQL/PostgreSQL, que também tem
criptografia de disco (TDE); a cifra por campo protege inclusive contra
quem tem acesso de leitura ao banco ou a um backup vazado.
"""
import os
from dataclasses import dataclass, field

from .crypto import FieldCipher
from .security import Role, hash_password


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    role: Role
    dealer_id: str
    active: bool = True


@dataclass
class Lead:
    id: str
    dealer_id: str
    customer_name: str
    cpf_enc: str
    cpf_index: str
    phone_enc: str
    vehicle_model: str
    vehicle_year: int
    months_since_last_visit: int
    churn_risk: float
    status: str = "novo"
    notes: list[str] = field(default_factory=list)


SERVICE_SHARE = {
    "SP01": {"period": "2026-08", "vehicles_in_territory": 4820, "vehicles_serviced": 2169},
    "RJ02": {"period": "2026-08", "vehicles_in_territory": 3110, "vehicles_serviced": 1182},
}


class Store:
    def __init__(self, cipher: FieldCipher):
        self.cipher = cipher
        self.users: dict[str, User] = {}
        self.leads: dict[str, Lead] = {}

    def add_user(self, uid: str, username: str, password: str, role: Role, dealer_id: str) -> None:
        self.users[username] = User(uid, username, hash_password(password), role, dealer_id)

    def add_lead(self, lid: str, dealer_id: str, name: str, cpf: str, phone: str,
                 model: str, year: int, months: int, risk: float) -> None:
        self.leads[lid] = Lead(
            id=lid, dealer_id=dealer_id, customer_name=name,
            cpf_enc=self.cipher.encrypt(cpf, "customer.cpf"),
            cpf_index=self.cipher.blind_index(cpf),
            phone_enc=self.cipher.encrypt(phone, "customer.phone"),
            vehicle_model=model, vehicle_year=year,
            months_since_last_visit=months, churn_risk=risk,
        )

    def find_lead_by_cpf(self, cpf: str) -> Lead | None:
        idx = self.cipher.blind_index(cpf)
        return next((lead for lead in self.leads.values() if lead.cpf_index == idx), None)


def seed_demo(store: Store) -> None:
    """Usuários de demonstração. A senha vem de DEMO_PASSWORD (nunca fica no código)."""
    password = os.environ.get("DEMO_PASSWORD")
    if not password:
        return
    store.add_user("u-100", "consultor.sp01", password, Role.CONSULTOR, "SP01")
    store.add_user("u-101", "gestor.sp01", password, Role.GESTOR, "SP01")
    store.add_user("u-200", "consultor.rj02", password, Role.CONSULTOR, "RJ02")
    store.add_user("u-900", "admin.ford", password, Role.ADMIN, "HQ")

    store.add_lead("L-1001", "SP01", "Cliente Sintético A", "11122233344", "11987654321",
                   "Ranger", 2021, 14, 0.78)
    store.add_lead("L-1002", "SP01", "Cliente Sintético B", "22233344455", "11912345678",
                   "Territory", 2022, 9, 0.52)
    store.add_lead("L-1003", "SP01", "Cliente Sintético C", "33344455566", "11955554444",
                   "Maverick", 2023, 4, 0.21)
    store.add_lead("L-2001", "RJ02", "Cliente Sintético D", "44455566677", "21988887777",
                   "Transit", 2020, 19, 0.86)
    store.add_lead("L-2002", "RJ02", "Cliente Sintético E", "55566677788", "21977776666",
                   "Bronco Sport", 2022, 7, 0.44)
