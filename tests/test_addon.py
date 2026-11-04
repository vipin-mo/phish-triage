import json
import shutil
import subprocess
from pathlib import Path

import pytest

ADDON = Path(__file__).parents[1] / "addon"


def test_the_manifest_asks_only_for_the_open_message_and_names_no_address():
    manifest = json.loads((ADDON / "appsscript.template.json").read_text())
    assert set(manifest["oauthScopes"]) == {
        "https://www.googleapis.com/auth/gmail.addons.execute",
        "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
        "https://www.googleapis.com/auth/script.external_request",
    }  # no gmail.readonly or mail.google.com: the add-on can't read any other email
    assert manifest["urlFetchWhitelist"] == ["__API_URL__/"]  # filled in by `make addon`, never committed
    assert manifest["addOns"]["gmail"]["contextualTriggers"][0]["onTriggerFunction"] == "onGmailMessageOpen"


def test_the_add_on_logs_nothing_and_names_no_address():
    code = (ADDON / "Code.js").read_text()
    assert "Logger.log" not in code and "console." not in code
    assert "execute-api" not in code and "amazonaws.com" not in code


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node to check the syntax")
def test_the_add_on_is_valid_javascript():
    subprocess.run(["node", "--check", str(ADDON / "Code.js")], check=True)  # noqa: S603, S607
