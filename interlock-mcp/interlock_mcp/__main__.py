"""Entry point: `interlock-mcp`, speaking MCP over stdio."""
from __future__ import annotations


def main() -> None:
    from interlock_mcp.server import server

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
