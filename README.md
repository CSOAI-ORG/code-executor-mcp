# Code Executor MCP Server

> By [MEOK AI Labs](https://meok.ai) — Sandboxed code execution for Python, JavaScript, and shell commands with safety guards

## Installation

```bash
pip install code-executor-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `execute_code`
Execute code in a sandboxed environment with safety checks. Dangerous patterns (os.system, eval, exec) are blocked.

**Parameters:**
- `code` (str): Code to execute
- `language` (str): Language — 'python' or 'javascript' (default 'python')
- `timeout` (int): Timeout in seconds (max 60, default 30)

### `run_command`
Execute a shell command with safety filters. Destructive commands are blocked.

**Parameters:**
- `command` (str): Shell command
- `timeout` (int): Timeout in seconds (max 60)

### `run_tests`
Run a test suite and return results with pass/fail summary.

**Parameters:**
- `test_command` (str): Test command (default 'python -m pytest')
- `working_dir` (str): Working directory
- `timeout` (int): Timeout in seconds (default 60)

### `read_file`
Read file contents from allowed directories (Desktop, Documents, Downloads, /tmp, sandbox).

**Parameters:**
- `path` (str): File path
- `limit` (int): Max lines to read (default 200)

### `list_sandbox_files`
List files in the sandbox working directory.

### `get_safety_rules`
Get current safety rules and blocked patterns.

### `execute_code_docker`
Execute code inside a temporary Docker container for full isolation.

**Parameters:**
- `code` (str): Code to execute
- `language` (str): Language — 'python', 'node', 'bash'
- `timeout_sec` (int): Timeout in seconds (default 30)

## Authentication

Free tier: 50 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
