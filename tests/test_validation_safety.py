from pathlib import Path

from app.services.validation_engine import SAFETY_METADATA


def test_safety_metadata_all_actions_false():
    assert SAFETY_METADATA == {
        "mode": "evidence_replay",
        "live_commands_executed": False,
        "environment_changes": False,
        "certificate_requested": False,
        "authentication_attempted": False,
        "configuration_changed": False,
        "arbitrary_command_execution": False,
    }


def test_phase1_implementation_has_no_live_execution_primitives():
    banned = [
        "sub" + "process",
        "os." + "system",
        "Invoke" + "-Expression",
        "power" + "shell.exe",
        "cmd" + ".exe",
        "cert" + "req",
        "Rube" + "us",
        "Cert" + "ipy",
        "Pass" + "TheCert",
        "shell" + "=True",
    ]
    files = [
        Path("app/services/validation_engine.py"),
        Path("app/services/validation_recipes.py"),
        Path("app/templates/simulation.html"),
        Path("app/templates/validation_run.html"),
        Path("app/static/js/validation.js"),
    ]
    for file_path in files:
        text = file_path.read_text()
        for pattern in banned:
            assert pattern not in text, f"{pattern} found in {file_path}"


def test_exposure_console_js_autostarts_and_has_dynamic_fallback():
    text = Path("app/static/js/validation.js").read_text()
    assert "DOMContentLoaded" in text
    assert "startTerminal();" in text
    assert "fallbackScript" in text
    assert "validation-run-data could not be parsed" in text
    assert "exposure-console-terminal" in text
    assert "allowedControls" in text
    assert "ANALYZE" in text
    assert "REQUEST" in text
    assert "AUTH" in text
    assert "FIX" in text
