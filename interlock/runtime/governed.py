"""Declaring which tools mutate the world, and how.

An ADK tool is just a Python callable, so on its own the runtime has no way to
know that `rollback_service` changes production while `read_logs` does not.
The `@governed` decorator attaches that missing metadata, binding a tool to an
entry in the action catalogue.

Tools without this decorator are not merely ungoverned — the plugin refuses to
run them at all. Forgetting to declare a tool fails closed.
"""
from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GovernedTool:
    tool_name: str
    action_type: str
    # Which keyword argument names the resource this action affects.
    target_param: str | None
    # Human-readable summary used in approval requests and the audit record.
    summary: str
    # Arguments copied verbatim into the proposal for scoring. Defaults to all.
    scored_params: tuple[str, ...] = field(default_factory=tuple)

    def extract_target(self, args: dict[str, Any]) -> str:
        if self.target_param and self.target_param in args:
            return str(args[self.target_param])
        for candidate in ("service", "instance", "bucket", "resource", "name", "target", "path"):
            if candidate in args:
                return str(args[candidate])
        return "unspecified"

    def extract_params(self, args: dict[str, Any]) -> dict[str, Any]:
        cleaned = {k: v for k, v in args.items() if k != "tool_context"}
        if not self.scored_params:
            return cleaned
        return {k: v for k, v in cleaned.items() if k in self.scored_params}


REGISTRY: dict[str, GovernedTool] = {}


def governed(
    *,
    action_type: str,
    summary: str,
    target_param: str | None = None,
    scored_params: tuple[str, ...] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Bind a tool function to an action catalogue entry."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        from interlock.blastradius.catalog import lookup

        if lookup(action_type) is None:
            # Catch the mistake at import time rather than at 3am.
            raise ValueError(
                f"tool '{fn.__name__}' declares action_type '{action_type}' "
                "which is not present in the action catalogue"
            )

        REGISTRY[fn.__name__] = GovernedTool(
            tool_name=fn.__name__,
            action_type=action_type,
            target_param=target_param,
            summary=summary,
            scored_params=scored_params,
        )

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await fn(*args, **kwargs)

        wrapper.__interlock_action_type__ = action_type  # type: ignore[attr-defined]
        return wrapper

    return decorator


def lookup_tool(tool_name: str) -> GovernedTool | None:
    return REGISTRY.get(tool_name)


def governed_tool_names() -> list[str]:
    return sorted(REGISTRY)


def action_types_for(tool_names: list[str]) -> list[str]:
    """Map tool names onto the action types they are allowed to perform."""
    return sorted({REGISTRY[n].action_type for n in tool_names if n in REGISTRY})
