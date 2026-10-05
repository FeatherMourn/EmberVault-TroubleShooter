"""Packaged runtime boundary for Control Center report-history requests."""

from collections.abc import Callable

from embervault_sdk import ModuleContext, ModuleResult

from .module import EncryptedReportHistory, execute_history_action


def handle_history_request(context: ModuleContext, request: dict,
                           history_factory: Callable[[str, bytes], EncryptedReportHistory],
                           key_resolver: Callable[[str], bytes]) -> ModuleResult:
    if not isinstance(request, dict) or request.get("contract_version") != 1:
        return ModuleResult("blocked", "History request requires contract version 1.")
    action = request.get("action")
    store_path = request.get("store_path")
    key_reference = request.get("key_reference")
    if not all(isinstance(value, str) and value.strip() for value in (action, store_path, key_reference)):
        return ModuleResult("blocked", "History request requires action, store path, and key reference.")
    if request.get("approved") is not True:
        return ModuleResult("blocked", "History request requires explicit approval.")
    try:
        key = key_resolver(key_reference)
        history = history_factory(store_path, key)
    except (KeyError, TypeError, ValueError) as exc:
        return ModuleResult("blocked", "History request could not resolve its key reference.", {"reason": str(exc)})
    return execute_history_action(context, history, action, True)
