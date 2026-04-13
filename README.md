# Code Executor MCP Server

> **By [MEOK AI Labs](https://meok.ai)** — Sovereign AI tools for everyone.

Sandboxed code execution for AI agents. Run Python, JavaScript, and shell commands with safety guards, output capture, timeout protection, and file access restrictions.

[![MCPize](https://img.shields.io/badge/MCPize-Listed-blue)](https://mcpize.com/mcp/code-executor)
[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `execute_code` | Execute code in a sandboxed environment with safety checks |
| `run_command` | Execute a shell command and return stdout/stderr/exit_code |
| `run_tests` | Run a test suite and return results |
| `read_file` | Read file contents (restricted to allowed directories) |
| `list_sandbox_files` | List files in the sandbox working directory |
| `get_safety_rules` | Get current safety rules and blocked patterns |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/code-executor-mcp.git
cd code-executor-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "code-executor": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/code-executor-mcp"
    }
  }
}
```

## Pricing

| Plan | Price | Requests |
|------|-------|----------|
| Free | $0/mo | 50 executions/day, 30s timeout |
| Pro | $9/mo | Unlimited, 120s timeout, Docker isolation |
| Enterprise | Contact us | Custom + network access + GPU execution |

[Get on MCPize](https://mcpize.com/mcp/code-executor)

## Part of MEOK AI Labs

This is one of 255+ MCP servers by MEOK AI Labs. Browse all at [meok.ai](https://meok.ai) or [GitHub](https://github.com/CSOAI-ORG).

---
**MEOK AI Labs** | [meok.ai](https://meok.ai) | nicholas@meok.ai | United Kingdom
