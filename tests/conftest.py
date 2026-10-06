"""Shared fixtures. All tests run with outbound networking disabled."""

from __future__ import annotations

import socket

import pytest

from trustgate.config import load_settings
from trustgate.rules import RuleEngine, build_engine


class NetworkBlocked(RuntimeError):
    pass


def _blocked(*_args, **_kwargs):
    raise NetworkBlocked("Network access is disabled in tests (links must only be analyzed statically).")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)


@pytest.fixture(scope="session")
def settings():
    # Ignore any developer .env so tests are deterministic.
    return load_settings(env={})


@pytest.fixture(scope="session")
def engine(settings) -> RuleEngine:
    return build_engine(settings)
