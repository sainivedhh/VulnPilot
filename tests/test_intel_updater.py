from __future__ import annotations

import httpx
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vulnpilot.intel.updater import update_epss, update_kev


def test_update_kev_success(tmp_path: Path) -> None:
    dest = tmp_path / "kev.json"
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"vulnerabilities": []}
    mock_resp.content = b'{"vulnerabilities": []}'

    with patch("httpx.get", return_value=mock_resp):
        assert update_kev(output=dest) is True
    assert dest.exists()


def test_update_kev_http_error(tmp_path: Path) -> None:
    dest = tmp_path / "kev.json"
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError("error", request=MagicMock(), response=MagicMock())

    with patch("httpx.get", return_value=mock_resp):
        assert update_kev(output=dest) is False
    assert not dest.exists()


def test_update_epss_success(tmp_path: Path) -> None:
    dest = tmp_path / "epss.json"
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "version": "1",
        "score_date": "2024",
        "data": [{"cve": "CVE-1", "epss": "0.5", "percentile": "0.9"}]
    }

    with patch("httpx.get", return_value=mock_resp):
        assert update_epss(output=dest) is True
    assert dest.exists()


def test_update_epss_network_error(tmp_path: Path) -> None:
    dest = tmp_path / "epss.json"
    with patch("httpx.get", side_effect=httpx.ConnectError("timeout")):
        assert update_epss(output=dest) is False
    assert not dest.exists()
