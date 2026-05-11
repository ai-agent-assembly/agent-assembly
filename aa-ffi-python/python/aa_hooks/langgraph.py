"""LangGraph adapter — intercepts node→node message transitions.

Called by the Rust hook registry when ``langgraph`` is detected in
``sys.modules``.  Patches ``StateGraph.compile`` so that every compiled
graph wraps its node invocations and records ``Messages`` edges via the
``AssemblyHandle`` when control moves from one node to another.

Safety guarantees
-----------------
* Graph behaviour and return values are never modified.
* Hook failures are caught and silently dropped.
* The patch is idempotent — a second ``install()`` call is a no-op.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("aa_hooks.langgraph")

_installed: bool = False
_original_compile: Any | None = None


def install(handle: Any) -> None:
    """Patch ``langgraph.graph.StateGraph.compile`` to emit ``Messages`` edges."""
    global _installed, _original_compile

    try:
        from langgraph.graph import StateGraph  # type: ignore[import]
    except ImportError as exc:
        import warnings
        warnings.warn(
            f"aa_hooks.langgraph: langgraph not importable, skipping hook: {exc}",
            stacklevel=2,
        )
        return

    if _installed:
        logger.debug("langgraph hook already installed, skipping")
        return

    _original_compile = StateGraph.compile

    def _patched_compile(self: Any, *args: Any, **kwargs: Any) -> Any:
        graph = _original_compile(self, *args, **kwargs)
        return _wrap_graph(graph, handle)

    StateGraph.compile = _patched_compile  # type: ignore[method-assign]
    _installed = True
    logger.info("langgraph hook installed")


def _wrap_graph(graph: Any, handle: Any) -> Any:
    """Wrap a compiled LangGraph so that node→node transitions emit edges."""
    original_invoke = getattr(graph, "invoke", None)
    original_ainvoke = getattr(graph, "ainvoke", None)

    if original_invoke is not None:
        def _wrapped_invoke(state: Any, *args: Any, **kwargs: Any) -> Any:
            result = original_invoke(state, *args, **kwargs)
            _emit_edge(handle, state, result)
            return result

        graph.invoke = _wrapped_invoke

    if original_ainvoke is not None:
        async def _wrapped_ainvoke(state: Any, *args: Any, **kwargs: Any) -> Any:
            result = await original_ainvoke(state, *args, **kwargs)
            _emit_edge(handle, state, result)
            return result

        graph.ainvoke = _wrapped_ainvoke

    return graph


def _emit_edge(handle: Any, state: Any, result: Any) -> None:
    """Best-effort: emit a ``messages`` edge when node context is available."""
    try:
        source_id = _extract_agent_id(state, "source_agent_id")
        target_id = _extract_agent_id(result, "target_agent_id")
        if source_id and target_id:
            handle.report_edge(
                source_agent_id=source_id,
                target_agent_id=target_id,
                edge_type="messages",
                metadata_json=None,
            )
    except Exception:
        logger.debug("langgraph hook: failed to emit edge", exc_info=True)


def _extract_agent_id(obj: Any, key: str) -> str | None:
    """Extract an agent ID from a dict-like state object."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def uninstall() -> None:
    """Restore the original ``compile`` method. Used by tests."""
    global _installed, _original_compile

    if _original_compile is not None:
        try:
            from langgraph.graph import StateGraph  # type: ignore[import]
            StateGraph.compile = _original_compile  # type: ignore[method-assign]
        except ImportError:
            pass
        _original_compile = None

    _installed = False
