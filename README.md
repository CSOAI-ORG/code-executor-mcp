# Code Executor MCP Server

Sandboxed code execution for AI agents. Run Python, JavaScript, and shell commands with comprehensive safety guards, output capture, timeout protection, and file access restrictions. Built for production use with blocked destructive patterns and configurable limits.

## Tools

| Tool | Description |
|------|-------------|
| `execute_code` | Run Python or JavaScript code with safety checks and output capture |
| `run_command` | Execute shell commands with destructive-pattern blocking |
| `run_tests` | Run test suites (pytest, jest, etc.) with pass/fail summary |
| `read_file` | Read files within allowed directories |
| `list_sandbox_files` | List files in the execution sandbox |
| `get_safety_rules` | View current blocked patterns and safety configuration |

## Safety Features

- Blocks destructive shell commands: `rm -rf /`, fork bombs, pipe-to-shell
- Blocks dangerous Python: `os.system`, `subprocess`, `eval(input)`, raw sockets
- Blocks dangerous JavaScript: `child_process`, `require('fs')`, `eval()`
- File access restricted to Desktop, Documents, Downloads, /tmp
- All execution happens in an isolated temp directory
- Hard timeout cap at 60 seconds
- Output truncated at 10KB to prevent memory issues

## Installation

```bash
pip install mcp
```

Optional for JavaScript support:
```bash
brew install node  # or: apt install nodejs
```

## Usage

### Run the server

```bash
python server.py
```

### Claude Desktop config

```json
{
  "mcpServers": {
    "code-executor": {
      "command": "python",
      "args": ["/path/to/code-executor-mcp/server.py"]
    }
  }
}
```

### Example calls

**Execute Python:**
```
Tool: execute_code
Input: {"code": "import math\nprint(f'Pi = {math.pi:.10f}')\nprint(f'e = {math.e:.10f}')", "language": "python"}
Output: {"output": "Pi = 3.1415926536\ne = 2.7182818285\n", "exit_code": 0, "elapsed_seconds": 0.045}
```

**Run shell command:**
```
Tool: run_command
Input: {"command": "ls -la /tmp | head -20"}
Output: {"output": "total 128\ndrwxrwxrwt ...", "exit_code": 0, "elapsed_seconds": 0.012}
```

**Run tests:**
```
Tool: run_tests
Input: {"test_command": "python -m pytest tests/ -v", "working_dir": "/path/to/project"}
Output: {"passed": true, "summary": "12 passed in 1.34s", "exit_code": 0}
```

**Blocked command example:**
```
Tool: run_command
Input: {"command": "rm -rf /"}
Output: {"error": "Command blocked by safety filter (matches: rm\\s+-rf\\s+/)"}
```

## Pricing

| Tier | Limit | Price |
|------|-------|-------|
| Free | 50 executions/day, 30s timeout | $0 |
| Pro | Unlimited, 120s timeout, Docker isolation | $9/mo |
| Enterprise | Custom + network access + GPU execution | Contact us |

## License

MIT
