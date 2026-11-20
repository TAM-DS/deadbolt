"""deadbolt — command line interface.

Exit codes: 0 clean (below --fail-on) · 1 findings at/above --fail-on · 2 usage/runtime error
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__, proposals, report
from .engine import ScanOptions, run
from .models import Severity
from .rules import ALL_RULES
from .redaction import sanitize_text


def _sev(v: str) -> Severity:
    try:
        return Severity.parse(v)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", "-f", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--output", "-o", type=Path, help="write report to file instead of stdout")
    p.add_argument("--fail-on", type=_sev, default=Severity.HIGH, help="exit 1 at/above this severity (default: high)")
    p.add_argument("--min-severity", type=_sev, default=Severity.INFO, help="hide findings below this severity")
    p.add_argument("--baseline", type=Path, help="JSON baseline of accepted finding ids")
    p.add_argument("--proposals", type=Path, help="write hashed, human-approval revocation proposals here")
    p.add_argument("--jobs", "-j", type=int, default=0, help="worker processes (default: auto)")
    p.add_argument("--exclude", action="append", default=[], help="glob to skip (repeatable)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--llm-triage", action="store_true",
                   help="add narrative notes via a LOCAL Ollama model (loopback only; never sees secrets)")
    p.add_argument("--llm-model", default="llama3.1:8b")
    p.add_argument("--llm-host", default="http://127.0.0.1:11434")


def _emit(result, args) -> int:
    triage_failed = False
    if args.llm_triage:
        from .triage_llm import annotate
        try:
            n = annotate(result.findings, model=args.llm_model, host=args.llm_host, stats=result)
            print(f"deadbolt: local LLM annotated {n} findings", file=sys.stderr)
        except (PermissionError, RuntimeError) as e:
            print(f"deadbolt: {sanitize_text(str(e))}; deterministic scan results follow", file=sys.stderr)
            triage_failed = True

    if args.proposals:
        props = proposals.build_all(result.findings)
        args.proposals.parent.mkdir(parents=True, exist_ok=True)
        args.proposals.write_text(json.dumps({"generated_by": f"deadbolt {__version__}", "proposals": props}, indent=2))
        print(f"deadbolt: wrote {len(props)} revocation proposals → {args.proposals} "
              f"(nothing executed; approve with `deadbolt approve <id>`)", file=sys.stderr)

    out = args.output.open("w") if args.output else sys.stdout
    try:
        if args.format == "json":
            report.dump(report.to_json(result), out)
        elif args.format == "sarif":
            report.dump(report.to_sarif(result), out)
        else:
            report.render_text(result, out, color=False if (args.no_color or args.output) else None)
    finally:
        if args.output:
            out.close()
            print(f"deadbolt: report written to {args.output}", file=sys.stderr)
    if triage_failed:
        return 2
    return 1 if any(f.severity >= args.fail_on for f in result.findings) else 0


def cmd_audit(args) -> int:
    opts = ScanOptions(staged=args.staged, history=args.history, max_commits=args.max_commits, jobs=args.jobs,
                       baseline=args.baseline, min_severity=args.min_severity, exclude=args.exclude)
    if not args.path.exists():
        print(f"deadbolt: no such path: {args.path}", file=sys.stderr)
        return 2
    return _emit(run(args.path, opts), args)


def cmd_demo(args) -> int:
    from .fixtures import generate
    out = args.out or Path(tempfile.mkdtemp(prefix="deadbolt-demo-")) / "dirty-repo"
    generate(out)
    print(f"deadbolt: synthetic dirty repo generated at {out} (all credentials are fake)\n", file=sys.stderr)
    opts = ScanOptions(history=True, jobs=args.jobs, min_severity=args.min_severity, exclude=args.exclude)
    return _emit(run(out, opts), args)


def cmd_fixtures(args) -> int:
    from .fixtures import generate
    out = generate(args.out, seed=args.seed, with_git=not args.no_git)
    print(f"generated synthetic dirty repo at {out}")
    return 0


def cmd_baseline(args) -> int:
    result = run(args.path, ScanOptions(history=args.history))
    data = {"generated_by": f"deadbolt {__version__}",
            "findings": [{"id": f.key, "rule_id": f.rule_id, "path": f.location.path} for f in result.findings]}
    args.output.write_text(json.dumps(data, indent=2) + "\n")
    print(f"baseline of {len(result.findings)} findings written to {args.output}")
    return 0


def cmd_decide(args, decision: str) -> int:
    try:
        entry = proposals.record_decision(args.proposals, args.ledger, args.proposal_id, decision,
                                          approver=args.by, reason=args.reason)
    except (LookupError, PermissionError, ValueError, FileNotFoundError) as e:
        print(f"deadbolt: {sanitize_text(str(e))}", file=sys.stderr)
        return 2
    print(f"{decision}d {entry['proposal_id'][:16]} by {entry['approver']} → {args.ledger} "
          f"(entry {entry['entry_hash']})")
    print("DeadBolt has not executed anything. Carry out the runbook steps, then baseline the finding.")
    return 0


def cmd_ledger(args) -> int:
    ok, msg = proposals.verify_ledger(args.ledger, expected_head=args.expected_head)
    print(("✔ " if ok else "✘ ") + msg)
    return 0 if ok else 1


def cmd_rules(_args) -> int:
    for r in ALL_RULES:
        print(f"{r.id:14} {r.authority.label:8} {'$' if r.spend else ' '} {r.title}")
    from .report import AGENT_RULE_TITLES
    for rid, title in AGENT_RULE_TITLES.items():
        print(f"{rid:14} {'agentic':8}   {title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="deadbolt", description="Offline secret & agent-authority scanner.")
    p.add_argument("--version", action="version", version=f"deadbolt {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="scan a directory, file, archive or docker-save tarball")
    a.add_argument("path", nargs="?", type=Path, default=Path("."))
    a.add_argument("--staged", action="store_true", help="scan only the git index (pre-commit mode)")
    a.add_argument("--history", action="store_true", help="also scan added lines across git history")
    a.add_argument("--max-commits", type=int, default=1000)
    _add_scan_args(a)
    a.set_defaults(func=cmd_audit)

    d = sub.add_parser("demo", help="generate the synthetic dirty repo and audit it (zero setup)")
    d.add_argument("--out", type=Path)
    _add_scan_args(d)
    d.set_defaults(func=cmd_demo)

    fx = sub.add_parser("fixtures", help="generate the synthetic dirty repo only")
    fx.add_argument("--out", type=Path, default=Path("fixtures/dirty-repo"))
    fx.add_argument("--seed", type=int, default=4471)
    fx.add_argument("--no-git", action="store_true")
    fx.set_defaults(func=cmd_fixtures)

    b = sub.add_parser("baseline", help="record current findings as accepted")
    b.add_argument("path", nargs="?", type=Path, default=Path("."))
    b.add_argument("--output", "-o", type=Path, default=Path(".deadbolt-baseline.json"))
    b.add_argument("--history", action="store_true")
    b.set_defaults(func=cmd_baseline)

    for name in ("approve", "reject"):
        c = sub.add_parser(name, help=f"{name} a revocation proposal (append-only, hash-chained ledger)")
        c.add_argument("proposal_id", help="proposal id or unique prefix")
        c.add_argument("--proposals", type=Path, default=Path("deadbolt-proposals.json"))
        c.add_argument("--ledger", type=Path, default=Path(".deadbolt/approvals.jsonl"))
        c.add_argument("--by", help="approver identity (default: current user)")
        c.add_argument("--reason", default="")
        c.set_defaults(func=lambda a, _n=name: cmd_decide(a, _n))

    lg = sub.add_parser("ledger", help="verify the approval ledger hash chain")
    lg.add_argument("--ledger", type=Path, default=Path(".deadbolt/approvals.jsonl"))
    lg.add_argument("--expected-head", help="trusted SHA-256 head stored separately from the ledger")
    lg.set_defaults(func=cmd_ledger)

    r = sub.add_parser("rules", help="list detection rules")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:  # e.g. `deadbolt rules | head`
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except (RuntimeError, OSError, ValueError) as e:
        print(f"deadbolt: {sanitize_text(str(e))}", file=sys.stderr)
        return 2
