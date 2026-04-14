#!/usr/bin/env python3
"""
Code Executor MCP Server
=========================
Sandboxed code execution and shell command runner for AI agents. Execute Python,
JavaScript, and shell commands with safety guards, output capture, timeout
protection, and file I/O restrictions.

Install: pip install mcp
Run:     python server.py
"""

import json
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
FREE_DAILY_LIMIT = 50
_usage: dict[str, list[datetime]] = defaultdict(list)


def _check_rate_limit(caller: str = "anonymous") -> Optional[str]:
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return f"Free tier limit reached ({FREE_DAILY_LIMIT}/day). Upgrade to Pro: https://mcpize.com/code-executor-mcp/pro"
    _usage[caller].append(now)
    return None


# ---------------------------------------------------------------------------
# Safety Configuration
# ---------------------------------------------------------------------------
# Blocked shell command patterns
BLOCKED_COMMANDS = [
    r"rm\s+-rf\s+/",
    r"mkfs\.",
    r"dd\s+if=",
    r">\s*/dev/sd",
    r":\(\)\s*\{\s*:\s*\|\s*:",       # Fork bomb
    r"chmod\s+-R\s+777\s+/",
    r"curl\s+.*\|\s*(?:ba)?sh",       # Pipe to shell
    r"wget\s+.*\|\s*(?:ba)?sh",
    r"nc\s+-e",                        # Netcat reverse shell
    r"python.*-c.*import\s+os.*system",
    r"sudo\s+rm",
    r">\s*/etc/",
    r"mv\s+/",
    r"cat\s+/etc/(?:passwd|shadow|sudoers)",  # Read sensitive system files
    r"curl\s+.*>\s*/tmp/.*&&",                # Download-and-exec pattern
    r"\benv\b.*(?:pass|secret|key|token)",    # Environment variable leaks
    r"\bhistory\b",                           # Shell history leak
    r"base64\s+-d\s*\|",                      # Base64 decode pipe (obfuscation)
]

# Blocked Python code patterns
BLOCKED_PYTHON = [
    r"os\s*\.\s*system\s*\(",
    r"subprocess\.(?:call|run|Popen)\s*\(",
    r"shutil\.rmtree\s*\(\s*['\"]\/",
    r"__import__\s*\(",                        # Block ALL __import__ calls
    r"open\s*\(\s*['\"]\/etc",
    r"eval\s*\(",                              # Block all eval() calls
    r"exec\s*\(",                              # Block all exec() calls
    r"importlib\.import_module\s*\(",
    r"ctypes\.",
    r"socket\.\w+\s*\(",                       # No raw sockets
    r"__builtins__",                           # No builtins access
    r"globals\s*\(\s*\)",                      # No globals() access
    r"locals\s*\(\s*\)",                       # No locals() access
    r"getattr\s*\(",                           # No dynamic attribute access
    r"compile\s*\(",                           # No compile() calls
    r"from\s+os\s+import",                     # No 'from os import'
    r"from\s+subprocess\s+import",             # No 'from subprocess import'
    r"from\s+shutil\s+import",                 # No 'from shutil import'
    r"import\s+os\b",                          # No 'import os'
    r"import\s+subprocess\b",                  # No 'import subprocess'
    r"import\s+shutil\b",                      # No 'import shutil'
]

# Blocked JavaScript patterns
BLOCKED_JS = [
    r"child_process",
    r"require\s*\(\s*['\"]fs['\"]",
    r"process\.exit",
    r"eval\s*\(",
    r"Function\s*\(",
]

# Allowed directories for file operations
ALLOWED_DIRS = [
    str(Path.home() / "Desktop"),
    str(Path.home() / "Documents"),
    str(Path.home() / "Downloads"),
    "/tmp",
]

# Sandbox working directory
SANDBOX_DIR = Path(tempfile.gettempdir()) / "mcp-code-sandbox"
SANDBOX_DIR.mkdir(exist_ok=True)


def _check_command_safety(cmd: str) -> Optional[str]:
    """Returns error message if command is blocked, else None."""
    for pattern in BLOCKED_COMMANDS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return f"Command blocked by safety filter (matches: {pattern[:30]})"
    return None


def _check_python_safety(code: str) -> Optional[str]:
    """Returns error message if Python code is blocked, else None."""
    for pattern in BLOCKED_PYTHON:
        if re.search(pattern, code, re.IGNORECASE):
            return f"Code blocked by safety filter (matches: {pattern[:30]})"
    return None


def _check_js_safety(code: str) -> Optional[str]:
    """Returns error message if JavaScript code is blocked, else None."""
    for pattern in BLOCKED_JS:
        if re.search(pattern, code, re.IGNORECASE):
            return f"Code blocked by safety filter (matches: {pattern[:30]})"
    return None


def _check_path_allowed(path: str) -> bool:
    """Check if a file path is within allowed directories."""
    real = os.path.realpath(path)
    sandbox = str(SANDBOX_DIR)
    return any(real.startswith(d) for d in ALLOWED_DIRS + [sandbox])


# ---------------------------------------------------------------------------
# Execution Engines
# ---------------------------------------------------------------------------
def _run_python(code: str, timeout: int = 30) -> dict:
    """Execute Python code in a subprocess with safety checks."""
    safety = _check_python_safety(code)
    if safety:
        return {"error": safety}

    # Write to temp file for better error reporting
    script_path = SANDBOX_DIR / f"exec_{int(time.time())}.py"
    script_path.write_text(code)

    try:
        start = time.time()
        result = subprocess.run(
            ["python3", str(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(SANDBOX_DIR),
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        elapsed = round(time.time() - start, 3)

        return {
            "output": result.stdout[:10000],
            "error": result.stderr[:3000] if result.stderr else None,
            "exit_code": result.returncode,
            "elapsed_seconds": elapsed,
            "language": "python",
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Execution timed out after {timeout}s", "language": "python"}
    except Exception as e:
        return {"error": str(e), "language": "python"}
    finally:
        script_path.unlink(missing_ok=True)


def _run_javascript(code: str, timeout: int = 30) -> dict:
    """Execute JavaScript code using Node.js."""
    safety = _check_js_safety(code)
    if safety:
        return {"error": safety}

    script_path = SANDBOX_DIR / f"exec_{int(time.time())}.js"
    # Wrap in strict mode
    wrapped = f'"use strict";\n{code}'
    script_path.write_text(wrapped)

    try:
        start = time.time()
        result = subprocess.run(
            ["node", str(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(SANDBOX_DIR))
        elapsed = round(time.time() - start, 3)

        return {
            "output": result.stdout[:10000],
            "error": result.stderr[:3000] if result.stderr else None,
            "exit_code": result.returncode,
            "elapsed_seconds": elapsed,
            "language": "javascript",
        }
    except FileNotFoundError:
        return {"error": "Node.js not installed. Install: brew install node", "language": "javascript"}
    except subprocess.TimeoutExpired:
        return {"error": f"Execution timed out after {timeout}s", "language": "javascript"}
    except Exception as e:
        return {"error": str(e), "language": "javascript"}
    finally:
        script_path.unlink(missing_ok=True)


def _run_shell(command: str, timeout: int = 30) -> dict:
    """Execute a shell command with safety checks."""
    safety = _check_command_safety(command)
    if safety:
        return {"error": safety}

    try:
        start = time.time()
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=min(timeout, 60),  # Hard cap at 60s
            cwd=str(SANDBOX_DIR))
        elapsed = round(time.time() - start, 3)

        return {
            "output": result.stdout[:10000],
            "error": result.stderr[:3000] if result.stderr else None,
            "exit_code": result.returncode,
            "elapsed_seconds": elapsed,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "Code Executor MCP",
    instructions="Sandboxed code execution: Python, JavaScript, and shell commands with safety guards, output capture, and timeout protection.")


@mcp.tool()
def execute_code(code: str, language: str = "python", timeout: int = 30) -> dict:
    """Execute code in a sandboxed environment with safety checks.
    Supported languages: python, javascript.
    Timeout: max 60 seconds (30 default).
    Dangerous patterns (os.system, subprocess, eval(input), etc.) are blocked.
    Output is captured and returned (stdout + stderr, truncated at 10KB)."""
    err = _check_rate_limit()
    if err:
        return {"error": err}

    timeout = max(1, min(timeout, 60))

    if language == "python":
        return _run_python(code, timeout)
    elif language in ("javascript", "js", "node"):
        return _run_javascript(code, timeout)
    else:
        return {"error": f"Unsupported language: {language}. Supported: python, javascript"}


@mcp.tool()
def run_command(command: str, timeout: int = 30) -> dict:
    """Execute a shell command and return stdout/stderr/exit_code.
    Timeout: max 60 seconds.
    Destructive commands (rm -rf /, dd, fork bombs, pipe-to-shell) are blocked.
    Commands run in a temporary sandbox directory."""
    err = _check_rate_limit()
    if err:
        return {"error": err}

    if not command.strip():
        return {"error": "No command provided"}

    return _run_shell(command, min(timeout, 60))


@mcp.tool()
def run_tests(test_command: str = "python -m pytest", working_dir: str = "",
              timeout: int = 60) -> dict:
    """Run a test suite and return results. Default: pytest.
    Specify working_dir to run tests in a specific project directory.
    Returns stdout, stderr, exit code, and pass/fail summary."""
    err = _check_rate_limit()
    if err:
        return {"error": err}

    # Safety check on the test command (same as shell commands)
    safety = _check_command_safety(test_command)
    if safety:
        return {"error": safety}

    cwd = working_dir if working_dir and os.path.isdir(working_dir) else str(SANDBOX_DIR)

    try:
        start = time.time()
        result = subprocess.run(
            test_command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=min(timeout, 120),
            cwd=cwd)
        elapsed = round(time.time() - start, 3)

        # Parse pytest output for summary
        output = result.stdout
        summary = ""
        for line in output.split("\n"):
            if "passed" in line or "failed" in line or "error" in line:
                summary = line.strip()
                break

        return {
            "output": output[:10000],
            "error": result.stderr[:3000] if result.stderr else None,
            "exit_code": result.returncode,
            "elapsed_seconds": elapsed,
            "summary": summary,
            "passed": result.returncode == 0,
            "working_dir": cwd,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Tests timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def read_file(path: str, limit: int = 200) -> dict:
    """Read contents of a file (restricted to allowed directories: Desktop,
    Documents, Downloads, /tmp, and the sandbox). Returns file content with
    line limit."""
    err = _check_rate_limit()
    if err:
        return {"error": err}

    if not path:
        return {"error": "No path provided"}

    if not _check_path_allowed(path):
        return {"error": "Access denied: path outside allowed directories"}

    try:
        with open(path, "r") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= limit:
                    break
                lines.append(line)
        content = "".join(lines)
        return {
            "content": content,
            "lines": len(lines),
            "truncated": len(lines) >= limit,
            "path": path,
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def list_sandbox_files() -> dict:
    """List files in the sandbox working directory. All code execution
    artifacts are stored here temporarily."""
    files = []
    for f in SANDBOX_DIR.iterdir():
        if f.is_file():
            stat = f.stat()
            files.append({
                "name": f.name,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    return {
        "sandbox_dir": str(SANDBOX_DIR),
        "files": sorted(files, key=lambda x: x["modified"], reverse=True),
        "count": len(files),
    }


@mcp.tool()
def get_safety_rules() -> dict:
    """Get the current safety rules and blocked patterns for code execution.
    Useful for understanding what is and isn't allowed."""
    return {
        "blocked_shell_patterns": BLOCKED_COMMANDS,
        "blocked_python_patterns": BLOCKED_PYTHON,
        "blocked_javascript_patterns": BLOCKED_JS,
        "allowed_file_directories": ALLOWED_DIRS,
        "sandbox_directory": str(SANDBOX_DIR),
        "max_timeout_seconds": 60,
        "max_output_bytes": 10000,
        "supported_languages": ["python", "javascript"],
    }


if __name__ == "__main__":
    mcp.run()
