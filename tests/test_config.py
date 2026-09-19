"""load_llm_config — LLM ayar dosyası okuma. Faz 0.3."""
from pathlib import Path

from pentestai.config import load_llm_config

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


def test_partial_config_only_returns_present_keys(tmp_path):
    p = tmp_path / "llm.yaml"
    p.write_text("llm:\n  provider: gemini\n", encoding="utf-8")
    cfg = load_llm_config(str(p))
    assert cfg == {"provider": "gemini"}


def test_example_config_parses_and_is_valid():
    cfg = load_llm_config(str(REPO_ROOT / "config" / "llm.example.yaml"))
    assert cfg["provider"] in {"none", "ollama", "gemini", "anthropic"}
    assert cfg["temperature"] == 0.0
