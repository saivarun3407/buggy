"""Unit tests for buggy_core.utils.config"""

from buggy_core.utils.config import BuggyConfig, load_config


class TestBuggyConfig:
    def test_default_values(self):
        config = BuggyConfig()
        assert config.debug is False

    def test_llm_defaults(self):
        config = BuggyConfig()
        assert config.llm.proxy_url == "http://localhost:4000"
        assert config.llm.proxy_api_key == "sk-buggy-master"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("BUGGY_DEBUG", "true")
        config = BuggyConfig()
        assert config.debug is True


class TestLoadConfig:
    def test_returns_defaults(self):
        config = load_config()
        assert config.llm.proxy_url == "http://localhost:4000"
