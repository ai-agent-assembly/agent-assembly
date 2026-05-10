"""OpenAI Agents SDK adapter — intercepts agent handoffs.

Called by the Rust hook registry when ``openai-agents`` is detected in
``sys.modules``.  Patches the handoff mechanism so that every agent
handoff (orchestrator → worker) records a ``DelegatesTo`` edge via the
``AssemblyHandle``.

Safety guarantees
-----------------
* Handoff behaviour and return values are never modified.
* Hook failures are caught and silently dropped.
* The patch is idempotent — a second ``install()`` call is a no-op.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("aa_hooks.openai_agents")

_installed: bool = False
_original_handoff: Any | None = None


def install(handle: Any) -> None:
    """Patch the OpenAI Agents SDK handoff mechanism to emit ``DelegatesTo`` edges."""
    global _installed, _original_handoff

    try:
        from agents import handoff as _handoff_module  # type: ignore[import]
        target = _handoff_module
    except ImportError:
        try:
            import openai_agents as _oa  # type: ignore[import]
            target = _oa
        except ImportError as exc:
            import warnings
            warnings.warn(
                f"aa_hooks.openai_agents: openai-agents not importable, skipping hook: {exc}",
                stacklevel=2,
            )
            return

    if _installed:
        logger.debug("openai_agents hook already installed, skipping")
        return

    original_fn = getattr(target, "handoff", None)
    if original_fn is None:
        logger.debug("openai_agents hook: handoff() not found, skipping")
        return

    _original_handoff = original_fn

    def _wrapped_handoff(*args: Any, **kwargs: Any) -> Any:
        result = original_fn(*args, **kwargs)
        _emit_handoff_edge(handle, args, kwargs)
        return result

    target.handoff = _wrapped_handoff  # type: ignore[attr-defined]
    _installed = True
    logger.info("openai_agents hook installed")


def _emit_handoff_edge(handle: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Best-effort: emit a ``delegates_to`` edge from handoff call arguments."""
    try:
        source_id = kwargs.get("source_agent_id") or (args[0] if args else None)
        target_id = kwargs.get("target_agent_id") or (args[1] if len(args) > 1 else None)
        if source_id and target_id:
            handle.report_edge(
                source_agent_id=str(source_id),
                target_agent_id=str(target_id),
                edge_type="delegates_to",
                metadata_json=None,
            )
    except Exception:
        logger.debug("openai_agents hook: failed to emit handoff edge", exc_info=True)


def uninstall() -> None:
    """Restore the original ``handoff`` function. Used by tests."""
    global _installed, _original_handoff

    if _original_handoff is not None:
        try:
            from agents import handoff as _handoff_module  # type: ignore[import]
            _handoff_module.handoff = _original_handoff  # type: ignore[attr-defined]
        except ImportError:
            pass
        _original_handoff = None

    _installed = False
