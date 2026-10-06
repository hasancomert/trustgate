from pathlib import Path

import pytest
from pydantic import ValidationError

from trustgate.config import DEFAULT_CONFIG_PATH, PROJECT_ROOT, load_settings


def test_defaults_from_toml(settings):
    assert settings.llm.base_url == "https://api.featherless.ai/v1"
    assert settings.llm.model == "Qwen/Qwen2.5-14B-Instruct"
    assert settings.scoring.thresholds.suspicious < settings.scoring.thresholds.dangerous
    assert settings.ml.resolved_model_path() == PROJECT_ROOT / "models" / "tfidf_lr.joblib"


def test_env_overrides_llm_connection():
    s = load_settings(env={"LLM_BASE_URL": "http://localhost:9999/v1", "LLM_MODEL": "other/model", "LLM_API_KEY": "k", "LLM_TIMEOUT_SECONDS": "5"})
    assert s.llm.base_url == "http://localhost:9999/v1"
    assert s.llm.model == "other/model"
    assert s.llm.timeout_seconds == 5
    assert s.llm.live_enabled


@pytest.mark.parametrize(
    "env,expected",
    [({}, False), ({"LLM_API_KEY": "x"}, True), ({"LLM_API_KEY": "x", "LLM_MODE": "mock"}, False), ({"LLM_MODE": "LIVE"}, True)],
)
def test_llm_mode_resolution(env, expected):
    assert load_settings(env=env).llm.live_enabled is expected


def test_invalid_thresholds_rejected(tmp_path: Path):
    bad = DEFAULT_CONFIG_PATH.read_text().replace("suspicious = 35", "suspicious = 90")
    path = tmp_path / "settings.toml"
    path.write_text(bad)
    with pytest.raises(ValidationError):
        load_settings(path=path, env={})
