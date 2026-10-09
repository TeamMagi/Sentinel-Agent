"""load_llm_config / load_scope_config / load_actors / load_endpoints — YAML config yükleyiciler."""
from pathlib import Path

import pytest

from pentestai.config import load_actors, load_endpoints, load_llm_config, load_scope_config

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_reads_all_fields(tmp_path):
    p = tmp_path / "llm.yaml"
    p.write_text(
        "llm:\n"
        "  provider: ollama\n"
        "  model: qwen2.5:14b-instruct\n"
        "  host: http://localhost:11434\n"
        "  temperature: 0\n"
        "  max_tokens: 1024\n",
        encoding="utf-8",
    )
    cfg = load_llm_config(str(p))
    assert cfg["provider"] == "ollama"
    assert cfg["model"] == "qwen2.5:14b-instruct"
    assert cfg["host"] == "http://localhost:11434"
    assert cfg["temperature"] == 0.0
    assert cfg["max_tokens"] == 1024


def test_missing_file_returns_empty_dict(tmp_path):
    assert load_llm_config(str(tmp_path / "yok.yaml")) == {}


def test_reads_think_flag(tmp_path):
    # Reasoning modeli için düşünme aç/kapat bayrağı (yalnızca ollama'da kullanılır).
    p = tmp_path / "llm.yaml"
    p.write_text("llm:\n  provider: ollama\n  model: qwen3.8:27b\n  think: false\n", encoding="utf-8")
    cfg = load_llm_config(str(p))
    assert cfg["think"] is False
    assert cfg["model"] == "qwen3.8:27b"


def test_partial_config_only_returns_present_keys(tmp_path):
    p = tmp_path / "llm.yaml"
    p.write_text("llm:\n  provider: gemini\n", encoding="utf-8")
    cfg = load_llm_config(str(p))
    assert cfg == {"provider": "gemini"}


def test_example_config_parses_and_is_valid():
    cfg = load_llm_config(str(REPO_ROOT / "config" / "llm.example.yaml"))
    assert cfg["provider"] in {"none", "ollama", "gemini", "anthropic"}
    assert cfg["temperature"] == 0.0


# --- load_scope_config ---

def test_load_scope_config_full(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "target:\n"
        "  base_url: http://juice-shop:3000\n"
        "scope:\n"
        "  allowed_hosts: [juice-shop]\n"
        "  allowed_ports: [3000]\n"
        "  allowed_path_prefixes: [/rest, /api]\n"
        "  denied_path_patterns: ['^/admin']\n"
        "  allowed_methods: [GET, POST]\n"
        "  destructive_tests: true\n"
        "  external_network: true\n"
        "budget:\n"
        "  max_payload_bytes: 2048\n"
        "  max_total_requests: 50\n"
        "  max_rps_per_host: 2.5\n"
        "  max_wall_clock_sec: 120\n"
        "privacy:\n"
        "  no_secrets_in_query: false\n",
        encoding="utf-8",
    )
    target, scope, budget = load_scope_config(str(p))
    assert target == "http://juice-shop:3000"
    assert scope.allowed_hosts == ["juice-shop"]
    assert scope.allowed_ports == [3000]
    assert scope.allowed_path_prefixes == ["/rest", "/api"]
    assert scope.denied_path_patterns == ["^/admin"]
    assert scope.allowed_methods == ["GET", "POST"]
    assert scope.destructive_tests is True
    assert scope.external_network is True
    assert scope.max_payload_bytes == 2048
    assert scope.no_secrets_in_query is False
    assert budget.max_total_requests == 50
    assert budget.max_rps_per_host == 2.5
    assert budget.max_wall_clock_sec == 120


def test_load_scope_config_defaults(tmp_path):
    # target/budget/privacy bölümleri tamamen atlanabilir — hepsi güvenli varsayılana düşer.
    p = tmp_path / "scope.yaml"
    p.write_text(
        "scope:\n"
        "  allowed_hosts: [localhost]\n"
        "  allowed_ports: [8080]\n",
        encoding="utf-8",
    )
    target, scope, budget = load_scope_config(str(p))
    assert target == ""
    assert scope.allowed_path_prefixes == ["/"]
    assert scope.denied_path_patterns == []
    assert scope.allowed_methods == ["GET", "HEAD"]
    assert scope.destructive_tests is False
    assert scope.external_network is False
    assert scope.max_payload_bytes == 1_048_576
    assert scope.no_secrets_in_query is True
    assert budget.max_total_requests == 2000
    assert budget.max_rps_per_host == 5
    assert budget.max_wall_clock_sec == 900


def test_load_scope_config_empty_file_missing_required_keys(tmp_path):
    # allowed_hosts/allowed_ports zorunlu — scope bölümü boşsa KeyError ile patlamalı (sessiz geçmemeli).
    p = tmp_path / "scope.yaml"
    p.write_text("", encoding="utf-8")
    with pytest.raises(KeyError):
        load_scope_config(str(p))


def test_example_scope_config_parses():
    target, scope, budget = load_scope_config(str(REPO_ROOT / "config" / "scope.example.yaml"))
    assert isinstance(scope.allowed_hosts, list) and scope.allowed_hosts
    assert isinstance(scope.allowed_ports, list) and scope.allowed_ports
    assert budget.max_total_requests > 0


# --- load_actors ---

def test_load_actors_full(tmp_path):
    p = tmp_path / "actors.yaml"
    p.write_text(
        "actors:\n"
        "  - name: user_victim\n"
        "    role: user\n"
        "    own_object_ids: {basket: 6, order: 12}\n"
        "    auth: {type: static, headers: {Authorization: 'Bearer x'}}\n"
        "  - name: admin\n"
        "    role: admin\n",
        encoding="utf-8",
    )
    out = load_actors(str(p))
    assert len(out) == 2
    victim, victim_auth = out[0]
    assert victim.name == "user_victim"
    assert victim.role == "user"
    # own_object_ids değerleri her zaman str'a zorlanır (YAML int okur, model str bekler).
    assert victim.own_object_ids == {"basket": "6", "order": "12"}
    assert victim_auth == {"type": "static", "headers": {"Authorization": "Bearer x"}}

    admin, admin_auth = out[1]
    assert admin.name == "admin"
    assert admin.role == "admin"
    assert admin.own_object_ids == {}
    assert admin_auth == {}


def test_load_actors_empty_file(tmp_path):
    p = tmp_path / "actors.yaml"
    p.write_text("", encoding="utf-8")
    assert load_actors(str(p)) == []


def test_example_actors_config_parses():
    out = load_actors(str(REPO_ROOT / "config" / "actors.example.yaml"))
    assert len(out) >= 2
    names = [actor.name for actor, _ in out]
    assert len(names) == len(set(names))   # aktör adları benzersiz


# --- load_endpoints ---

def test_load_endpoints_full(tmp_path):
    p = tmp_path / "endpoints.yaml"
    p.write_text(
        "endpoints:\n"
        "  - method: GET\n"
        "    path_template: /rest/basket/{id}\n"
        "    id_param: id\n"
        "    id_location: path\n"
        "    resource_key: basket\n"
        "  - path_template: /api/orders\n",
        encoding="utf-8",
    )
    out = load_endpoints(str(p))
    assert len(out) == 2
    ep0, key0 = out[0]
    assert ep0.method == "GET"
    assert ep0.path_template == "/rest/basket/{id}"
    assert ep0.id_param == "id"
    assert ep0.id_location == "path"
    assert key0 == "basket"

    # method/id_param/id_location/resource_key verilmezse varsayılanlar devreye girer.
    ep1, key1 = out[1]
    assert ep1.method == "GET"
    assert ep1.id_param == "id"
    assert ep1.id_location == "path"
    assert key1 == "id"


def test_load_endpoints_empty_file(tmp_path):
    p = tmp_path / "endpoints.yaml"
    p.write_text("", encoding="utf-8")
    assert load_endpoints(str(p)) == []


def test_example_endpoints_config_parses():
    out = load_endpoints(str(REPO_ROOT / "config" / "endpoints.example.yaml"))
    assert len(out) >= 1
    for ep, key in out:
        assert ep.path_template
        assert key
