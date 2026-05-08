<div align="center">

# Code Executor MCP

**MCP server for code executor mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-code-executor-mcp)](https://pypi.org/project/meok-code-executor-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Code Executor MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `execute_code` | Execute code in a sandboxed environment with safety checks. |
| `run_command` | Execute a shell command and return stdout/stderr/exit_code. |
| `run_tests` | Run a test suite and return results. Default: pytest. |
| `read_file` | Read contents of a file (restricted to allowed directories: Desktop, |
| `list_sandbox_files` | List files in the sandbox working directory. All code execution |
| `get_safety_rules` | Get the current safety rules and blocked patterns for code execution. |

## Installation

```bash
pip install meok-code-executor-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "code-executor-mcp": {
      "command": "python",
      "args": ["-m", "meok_code_executor_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 6 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
