"""The mailbox write plane is off unless the operator opts in, so the suite
turns it on once for the whole session. `test_write_optin.py` covers the
gate itself, including that the default is off."""

from __future__ import annotations

import pytest

from imap_mcp import server


@pytest.fixture(scope="session", autouse=True)
def _register_write_plane():
    server.register_write_tools()
