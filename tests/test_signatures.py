"""Tests for the salutation/signature config loader (D-007)."""
from pathlib import Path

import pytest

from app.signatures import REQUIRED_KEYS, SignaturesError, load_signatures

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "signatures.example.json"


def test_loads_repo_example_file():
    data = load_signatures(str(EXAMPLE))
    for key in REQUIRED_KEYS:
        assert key in data
        assert "html" in data[key]
    # The personal variant keeps the raw {{name}} placeholder (not substituted
    # server-side — the client fills it in).
    assert "{{name}}" in data["persoenliche_anrede"]["html"]


def test_missing_file_raises(tmp_path):
    with pytest.raises(SignaturesError):
        load_signatures(str(tmp_path / "does-not-exist.json"))


def test_broken_json_raises(tmp_path):
    p = tmp_path / "signatures.json"
    p.write_text("{ not valid json", encoding="utf-8")
    with pytest.raises(SignaturesError):
        load_signatures(str(p))


def test_missing_required_variant_raises(tmp_path):
    p = tmp_path / "signatures.json"
    p.write_text('{"firmenanrede": {"html": "<p>x</p>"}}', encoding="utf-8")
    with pytest.raises(SignaturesError):
        load_signatures(str(p))


def test_variant_without_html_raises(tmp_path):
    p = tmp_path / "signatures.json"
    p.write_text(
        '{"firmenanrede": {"from_name": "x"}, '
        '"persoenliche_anrede": {"html": "<p>y</p>"}}',
        encoding="utf-8",
    )
    with pytest.raises(SignaturesError):
        load_signatures(str(p))


def test_top_level_not_object_raises(tmp_path):
    p = tmp_path / "signatures.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(SignaturesError):
        load_signatures(str(p))
