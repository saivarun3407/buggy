"""Unit tests for the AST-based taint analyzer."""

from __future__ import annotations

import json
from pathlib import Path

from buggy.tools.research import taint_analyzer as ta


def _write_file(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content)
    return f


class TestAnalyzeFile:
    def test_python_sqli(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "app.py",
            "from flask import request\n"
            "def handler():\n"
            "    user_id = request.args.get('id')\n"
            "    cursor.execute('SELECT * FROM users WHERE id=' + user_id)\n",
        )
        findings = ta._analyze_file(f, "python")
        assert len(findings) >= 1
        assert findings[0]["vulnerability_type"] == "sql_injection"
        assert findings[0]["sanitized"] is False

    def test_python_sanitized(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "safe.py",
            "from flask import request\n"
            "def handler():\n"
            "    user_id = request.args.get('id')\n"
            "    safe_id = escape(user_id)\n"
            "    cursor.execute('SELECT * FROM users WHERE id=%s', [safe_id])\n",
        )
        findings = ta._analyze_file(f, "python")
        # The sanitizer (escape) should prevent this from being flagged
        assert len(findings) == 0

    def test_js_command_injection(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "handler.js",
            "const exec = require('child_process').exec;\n"
            "function handle(req, res) {\n"
            "    const cmd = req.query.command;\n"
            "    exec(cmd);\n"
            "}\n",
        )
        findings = ta._analyze_file(f, "javascript")
        assert len(findings) >= 1
        assert findings[0]["vulnerability_type"] == "command_injection"

    def test_no_source_no_findings(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "utils.py",
            "def add(a, b):\n    return a + b\n",
        )
        findings = ta._analyze_file(f, "python")
        assert len(findings) == 0

    def test_php_sqli(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "query.php",
            "<?php\n"
            "$name = $_GET['name'];\n"
            "mysql_query('SELECT * FROM users WHERE name=' . $name);\n",
        )
        findings = ta._analyze_file(f, "php")
        assert len(findings) >= 1
        assert findings[0]["vulnerability_type"] == "sql_injection"


class TestTaintAnalyzeCodebase:
    def test_scans_directory(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        _write_file(
            tmp_path,
            "src/app.py",
            "from flask import request\ndef view():\n    data = request.json\n    eval(data)\n",
        )
        _write_file(tmp_path, "src/clean.py", "print('hello')\n")
        result = json.loads(ta.taint_analyze_codebase.invoke({"root": str(tmp_path)}))
        assert result["files_scanned"] == 2
        assert result["total_findings"] >= 1

    def test_bad_root(self) -> None:
        result = json.loads(ta.taint_analyze_codebase.invoke({"root": "/nonexistent"}))
        assert result["error"] == "bad_request"


class TestTaintAnalyzeFile:
    def test_auto_detect_language(self, tmp_path: Path) -> None:
        f = _write_file(
            tmp_path,
            "test.py",
            "import os\nuser = os.environ['USER']\nos.system(user)\n",
        )
        result = json.loads(ta.taint_analyze_file.invoke({"file_path": str(f)}))
        assert result["language"] == "python"
        assert result["total_findings"] >= 1

    def test_file_not_found(self) -> None:
        result = json.loads(ta.taint_analyze_file.invoke({"file_path": "/nonexistent.py"}))
        assert result["error"] == "file_not_found"

    def test_unsupported_extension(self, tmp_path: Path) -> None:
        f = _write_file(tmp_path, "test.rs", "fn main() {}\n")
        result = json.loads(ta.taint_analyze_file.invoke({"file_path": str(f)}))
        assert result["error"] == "unsupported_language"


class TestTaintListSourcesSinks:
    def test_python(self) -> None:
        result = json.loads(ta.taint_list_sources_sinks.invoke({"language": "python"}))
        assert len(result["sources"]) > 0
        assert len(result["sinks"]) > 0

    def test_unsupported(self) -> None:
        result = json.loads(ta.taint_list_sources_sinks.invoke({"language": "brainfuck"}))
        assert result["error"] == "unsupported_language"
