import pytest


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    """Cada test parte de la configuración de ejemplo, sin claves del entorno del desarrollador."""
    import yaml

    from utils import helpers

    example = yaml.safe_load((helpers.PROJECT_ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    monkeypatch.setattr(helpers, "_config", example)
    for name in list(__import__("os").environ):
        if name.startswith("CYBERSWORD_") and name.endswith("_API_KEY"):
            monkeypatch.delenv(name)
