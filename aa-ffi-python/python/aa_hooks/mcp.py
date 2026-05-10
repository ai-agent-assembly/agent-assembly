"""MCP tool-call adapter — intercepts MCP client tool invocations.

Called by the Rust hook registry when ``mcp`` is detected in ``sys.modules``.
Patches the MCP client's ``call_tool`` method so that every tool invocation
records a ``Calls``, ``Reads``, or ``Writes`` edge via the ``AssemblyHandle``,
based on the tool's declared semantics.

Tool semantic mapping
---------------------
* Tools whose names start with ``read_``, ``get_``, ``list_``, ``fetch_`` → ``reads``
* Tools whose names start with ``write_``, ``set_``, ``put_``, ``create_``,
  ``update_``, ``delete_``, ``append_``, ``patch_`` → ``writes``
* All other tools → ``calls``

Safety guarantees
-----------------
* Tool call results are never modified.
* Hook failures are caught and silently dropped.
* The patch is idempotent — a second ``install()`` call is a no-op.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("aa_hooks.mcp")

_installed: bool = False
_original_call_tool: Any | None = None
_original_async_call_tool: Any | None = None

_READ_PREFIXES = ("read_", "get_", "list_", "fetch_", "search_", "query_")
_WRITE_PREFIXES = ("write_", "set_", "put_", "create_", "update_", "delete_", "append_", "patch_")


def _infer_edge_type(tool_name: str) -> str:
    name = tool_name.lower()
    if any(name.startswith(p) for p in _READ_PREFIXES):
        return "reads"
    if any(name.startswith(p) for p in _WRITE_PREFIXES):
        return "writes"
    return "calls"


def install(handle: Any) -> None:
    """Patch the MCP client to emit topology edges on tool calls."""
    global _installed, _original_call_tool, _original_async_call_tool

    try:
        from mcp import ClientSession  # type: ignore[import]
    except ImportError as exc:
        import warnings
        warnings.warn(
            f"aa_hooks.mcp: mcp package not importable, skipping hook: {exc}",
            stacklevel=2,
        )
        return

    if _installed:
        logger.debug("mcp hook already installed, skipping")
        return

    _original_call_tool = ClientSession.call_tool

    def _wrapped_call_tool(self: Any, tool_name: str, *args: Any, **kwargs: Any) -> Any:
        result = _original_call_tool(self, tool_name, *args, **kwargs)
        _emit_tool_edge(handle, tool_name, kwargs)
        return result

    ClientSession.call_tool = _wrapped_call_tool  # type: ignore[method-assign]

    original_async = getattr(ClientSession, "call_tool_async", None)
    if original_async is not None:
        _original_async_call_tool = original_async

        async def _wrapped_async(self: Any, tool_name: str, *args: Any, **kwargs: Any) -> Any:
            result = await original_async(self, tool_name, *args, **kwargs)
            _emit_tool_edge(handle, tool_name, kwargs)
            return result

        ClientSession.call_tool_async = _wrapped_async  # type: ignore[method-assign]

    _installed = True
    logger.info("mcp hook installed")


def _emit_tool_edge(handle: Any, tool_name: str, kwargs: dict[str, Any]) -> None:
    """Best-effort: emit an edge for this MCP tool call."""
    try:
        source_id = kwargs.get("source_agent_id")
        target_id = kwargs.get("target_agent_id") or kwargs.get("server_id")
        if source_id and target_id:
            edge_type = _infer_edge_type(tool_name)
            handle.report_edge(
                source_agent_id=str(source_id),
                target_agent_id=str(target_id),
                edge_type=edge_type,
                metadata_json=None,
            )
    except Exception:
        logger.debug("mcp hook: failed to emit tool edge", exc_info=True)


def uninstall() -> None:
    """Restore the original ``call_tool`` method. Used by tests."""
    global _installed, _original_call_tool, _original_async_call_tool

    if _original_call_tool is not None:
        try:
            from mcp import ClientSession  # type: ignore[import]
            ClientSession.call_tool = _original_call_tool  # type: ignore[method-assign]
        except ImportError:
            pass
        _original_call_tool = None

    if _original_async_call_tool is not None:
        try:
            from mcp import ClientSession  # type: ignore[import]
            ClientSession.call_tool_async = _original_async_call_tool  # type: ignore[method-assign]
        except ImportError:
            pass
        _original_async_call_tool = None

    _installed = False
