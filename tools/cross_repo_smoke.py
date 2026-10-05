from __future__ import annotations

import argparse
import importlib.util
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet
from embervault_sdk import ModuleContext


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("control_center", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    adapter = load_module("control_center_history_adapter", args.control_center / "core" / "troubleshooter_history_adapter.py")
    from src.module import EncryptedReportHistory
    from src.runtime import handle_history_request

    with tempfile.TemporaryDirectory() as temp:
        key = Fernet.generate_key()
        request = adapter.create_history_action_request("save", str(Path(temp) / "reports.enc"), "profile-key", True)
        result = adapter.dispatch_history_action(
            request,
            lambda context, payload: handle_history_request(
                context, payload, EncryptedReportHistory,
                lambda reference: key if reference == "profile-key" else (_ for _ in ()).throw(KeyError(reference))),
            ModuleContext("embervault.troubleshooter", "default", "EV-CROSS-REPO"),
        )
        assert result.status == "ready"
        assert result.data["action"] == "save"
        print("cross-repository history smoke test passed")


if __name__ == "__main__":
    main()
