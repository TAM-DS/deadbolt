"""Regression cases using synthetic credentials and isolated temporary repositories."""
import io
import json
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from deadbolt import agentic, cli, proposals, report, triage_llm
from deadbolt.engine import ScanOptions, run
from deadbolt.fixtures import _Gen, _tokens, generate
from deadbolt.models import Location
from deadbolt.sources import DEFAULT_MAX_BYTES


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.token = _tokens(_Gen())['github']

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(map(str, args)))
        return code, out.getvalue(), err.getvalue()

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Test',
                               '-c', 'user.email=test@example.invalid', *args],
                              capture_output=True, text=True, check=True).stdout

    def secret_file(self):
        path = self.root / 'app.py'
        path.write_text('TOKEN = "' + self.token + '"\n')
        return path

    def proposal_file(self):
        findings = run(self.secret_file(), ScanOptions()).findings
        path = self.root / 'props.json'
        entries = proposals.build_all(findings)
        path.write_text(json.dumps({'proposals': entries}))
        return path, entries[0]['proposal_id']

    def test_url_and_server_name_secrets_redacted_in_all_outputs(self):
        path = self.root / 'mcp.json'
        opaque = _Gen().s(30)
        path.write_text(json.dumps({'mcpServers': {self.token: {
            'url': 'http://example.invalid/mcp?token=' + self.token + '&other=' + opaque,
            'env': {'API_TOKEN': self.token}}}}))
        result = run(path, ScanOptions())
        output = io.StringIO()
        report.render_text(result, output, color=False)
        combined = output.getvalue() + json.dumps(report.to_json(result))
        combined += json.dumps(report.to_sarif(result)) + json.dumps(proposals.build_all(result.findings))
        self.assertTrue(result.findings)
        self.assertNotIn(self.token, combined)
        self.assertNotIn(opaque, combined)

    def test_demo_preserves_existing_directory(self):
        marker = self.root / 'keep.txt'
        marker.write_text('retain me')
        code, _, _ = self.invoke('demo', '--out', self.root)
        self.assertEqual(code, 2)
        self.assertEqual(marker.read_text(), 'retain me')

    def test_demo_refuses_symlink_destination(self):
        link = self.root / 'link'
        target = self.root / 'target'
        target.mkdir()
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            generate(link)
        self.assertTrue(target.exists())

    def test_corrupt_archive_is_incomplete(self):
        path = self.root / 'bad.tar'
        path.write_text('invalid archive')
        code, out, err = self.invoke('audit', path)
        self.assertEqual(code, 2)
        self.assertIn('Incomplete scan', err)
        self.assertNotIn('No findings', out)

    def test_oversized_file_is_incomplete_for_directory_and_file(self):
        path = self.root / 'large.py'
        path.write_text(' ' * DEFAULT_MAX_BYTES + self.token)
        for target in (self.root, path):
            with self.subTest(target=target):
                self.assertEqual(self.invoke('audit', target)[0], 2)

    def test_unreadable_file_is_incomplete(self):
        path = self.secret_file()
        with patch('pathlib.Path.open', side_effect=PermissionError('blocked')):
            self.assertEqual(self.invoke('audit', path)[0], 2)

    def test_staged_scan_uses_index_content_and_ignore(self):
        self.git('init', '-q')
        path = self.secret_file()
        self.git('add', 'app.py')
        path.write_text('TOKEN = None')
        (self.root / '.deadboltignore').write_text('app.py\n')
        self.assertEqual(self.invoke('audit', self.root, '--staged')[0], 1)
        self.git('add', '.deadboltignore')
        self.assertEqual(self.invoke('audit', self.root, '--staged')[0], 0)

    def test_staged_large_file_and_archive_are_not_silently_skipped(self):
        self.git('init', '-q')
        path = self.root / 'large.py'
        path.write_text(' ' * DEFAULT_MAX_BYTES + self.token)
        self.git('add', 'large.py')
        self.assertEqual(self.invoke('audit', self.root, '--staged')[0], 2)
        self.git('rm', '--cached', 'large.py')
        (self.root / 'image.tar').write_text('broken archive')
        self.git('add', 'image.tar')
        self.assertEqual(self.invoke('audit', self.root, '--staged')[0], 2)

    def test_history_limit_is_reported(self):
        generate(self.root / 'repo')
        code, _, err = self.invoke('audit', self.root / 'repo', '--history', '--max-commits', '1')
        self.assertEqual(code, 2)
        self.assertIn('Incomplete history scan', err)

    def test_manifest_grants_ignore_whitespace_and_list_position(self):
        doc = {'agents': [{'scopes': ['read', '*']}]}
        counts = []
        for indent in (None, 2):
            found = agentic.audit_agent_manifest('agent.json', json.dumps(doc, indent=indent), Location('agent.json'))
            counts.append(len(found))
        self.assertEqual(counts, [1, 1])

    def test_toml_auditing_and_missing_parser_error(self):
        text = '[mcp_servers.fs]\ncommand = "npx"\nargs = ["server-filesystem", "/"]\n'
        self.assertTrue(agentic.audit('config.toml', text, Location('config.toml')))
        with patch.object(agentic, 'tomllib', None):
            with self.assertRaises(RuntimeError):
                agentic.audit('config.toml', text, Location('config.toml'))

    def test_malformed_config_is_incomplete(self):
        path = self.root / 'mcp.json'
        path.write_text('{"mcpServers":')
        self.assertEqual(self.invoke('audit', path)[0], 2)

    def test_trusted_head_detects_rehash_and_truncation(self):
        path, pid = self.proposal_file()
        ledger = self.root / 'ledger.jsonl'
        entry = proposals.record_decision(path, ledger, pid, 'approve', approver='Tracy')
        trusted = entry['entry_hash']
        self.assertTrue(proposals.verify_ledger(ledger, trusted)[0])
        entry['approver'] = 'changed'
        entry['entry_hash'] = proposals.sha256(proposals.canonical({k: v for k, v in entry.items() if k != 'entry_hash'}))
        ledger.write_text(json.dumps(entry) + '\n')
        self.assertFalse(proposals.verify_ledger(ledger, trusted)[0])
        ledger.write_text('')
        self.assertFalse(proposals.verify_ledger(ledger, trusted)[0])
        self.assertIn('local integrity only', proposals.verify_ledger(ledger)[1])

    def test_malformed_ledger_returns_failure(self):
        ledger = self.root / 'ledger.jsonl'
        ledger.write_text('{bad json')
        self.assertEqual(self.invoke('ledger', '--ledger', ledger)[0], 1)

    def test_parallel_approvals_preserve_chain(self):
        path, pid = self.proposal_file()
        ledger = self.root / 'ledger.jsonl'
        with ThreadPoolExecutor(max_workers=4) as pool:
            entries = list(pool.map(lambda i: proposals.record_decision(path, ledger, pid, 'approve',
                                                                       approver=f'reviewer-{i}'), range(12)))
        self.assertEqual(len(ledger.read_text().splitlines()), 12)
        self.assertEqual(len({e['entry_hash'] for e in entries}), 12)
        self.assertTrue(proposals.verify_ledger(ledger)[0])

    def test_authority_explicitly_estimated(self):
        result = run(self.secret_file(), ScanOptions())
        blast = report.to_json(result)['findings'][0]['blast_radius']
        self.assertEqual(blast['effective_access'], 'unknown')
        self.assertIn('heuristic', blast['authority_basis'])

    def test_loopback_endpoint_validation(self):
        self.assertEqual(triage_llm._loopback_url('http://localhost:11434'), 'http://127.0.0.1:11434/api/generate')
        for host in ('http://example.invalid', 'http://127.0.0.1.example.invalid',
                     'http://user:password@127.0.0.1', 'http://127.0.0.1/?token=secret'):
            with self.subTest(host=host), self.assertRaises(PermissionError):
                triage_llm.annotate([], host=host)

    def test_local_http_success_redaction_and_accounting(self):
        received = []
        token = self.token
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({'response': 'Review token ' + token}).encode())
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            path = self.secret_file()
            base = run(path, ScanOptions())
            code, out, _ = self.invoke('audit', path, '--llm-triage', '--llm-host',
                                       f'http://127.0.0.1:{server.server_port}', '-f', 'json')
            data = json.loads(out)
            self.assertEqual(code, 1)
            self.assertEqual(data['stats']['network_calls'], 1)
            self.assertEqual(data['findings'][0]['blast_radius']['score'], base.findings[0].blast.score)
            self.assertNotIn(token, out)
            self.assertNotIn(token, json.dumps(received))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_model_failure_keeps_scan_report_and_returns_error(self):
        path = self.secret_file()
        with patch.object(triage_llm, 'annotate', side_effect=RuntimeError('Local LLM unavailable')):
            code, out, err = self.invoke('audit', path, '--llm-triage', '-f', 'json')
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(out)['findings'])
        self.assertIn('Local LLM unavailable', err)

    def test_redirect_is_refused_before_followup_request(self):
        request = urllib.request.Request('http://127.0.0.1:11434/api/generate', data=b'{}')
        for target in ('http://192.0.2.1/', 'http://127.0.0.1:8080/'):
            with self.subTest(target=target), self.assertRaises(PermissionError):
                triage_llm._NoRedirects().redirect_request(request, None, 302, 'Found', {}, target)

    def test_history_parses_full_config_after_single_field_change(self):
        self.git('init', '-q')
        path = self.root / 'mcp.json'
        doc = {'mcpServers': {'fs': {'command': 'npx', 'args': ['server-filesystem@1.2.3', '/project']}}}
        path.write_text(json.dumps(doc, indent=2))
        self.git('add', 'mcp.json')
        self.git('commit', '-qm', 'initial config')
        doc['mcpServers']['fs']['args'][-1] = '/'
        path.write_text(json.dumps(doc, indent=2))
        self.git('add', 'mcp.json')
        self.git('commit', '-qm', 'broaden scope')
        path.unlink()
        self.git('add', '-u')
        self.git('commit', '-qm', 'remove config')
        found = run(self.root, ScanOptions(history=True)).findings
        self.assertTrue(any(f.rule_id == 'DB-MCP-003' and f.location.origin == 'git-history' for f in found))

    def test_list_proposals_remain_supported(self):
        path, pid = self.proposal_file()
        path.write_text(json.dumps(json.loads(path.read_text())['proposals']))
        self.assertEqual(self.invoke('approve', pid, '--proposals', path,
                                     '--ledger', self.root / 'ledger.jsonl', '--by', 'Tracy')[0], 0)

    def test_live_redirect_is_blocked_without_external_request(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header('Location', 'http://192.0.2.1/blocked')
                self.end_headers()
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        visited = []
        original = urllib.request.HTTPHandler.http_open
        def checked(handler, request):
            visited.append(request.host)
            if not request.host.startswith('127.0.0.1:'):
                raise AssertionError('External request attempted')
            return original(handler, request)
        try:
            result = run(self.secret_file(), ScanOptions())
            with patch.object(urllib.request.HTTPHandler, 'http_open', checked):
                with self.assertRaises(PermissionError):
                    triage_llm.annotate(result.findings, host=f'http://127.0.0.1:{server.server_port}', stats=result)
            self.assertEqual(len(visited), 1)
            self.assertEqual(result.network_calls, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_malformed_local_model_response_is_reported(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"response": []}'
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        result = run(self.secret_file(), ScanOptions())
        with patch.object(urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(RuntimeError):
                triage_llm.annotate(result.findings, stats=result)
        self.assertEqual(result.network_calls, 1)
