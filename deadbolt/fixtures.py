"""Synthetic "dirty repo" generator.

Every credential below is random, deterministic (seeded) and FAKE. Tokens are
assembled at runtime from split prefixes so that this source file — and the
DeadBolt repository itself — contains no scannable secret. That is why the
fixture is generated rather than committed: GitHub push protection, and
DeadBolt's own CI self-scan, both stay green.

Scenario: an EV/energy company's edge-diagnostics team wired an AI
"maintenance copilot" into fleet telemetry using MCP servers.
"""

from __future__ import annotations

import base64
import io
import json
import random
import shutil
import subprocess
import tarfile
import textwrap
from pathlib import Path

from .rules import is_placeholder

UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LO = "abcdefghijklmnopqrstuvwxyz"
DIG = "0123456789"
B62 = UP + LO + DIG
B32 = UP + "234567"


class _Gen:
    def __init__(self, seed: int = 4471) -> None:
        self.r = random.Random(seed)

    def s(self, n: int, alphabet: str = B62) -> str:
        while True:
            v = "".join(self.r.choice(alphabet) for _ in range(n))
            if not is_placeholder(v):
                return v

    def b64(self, nbytes: int) -> str:
        return base64.b64encode(bytes(self.r.getrandbits(8) for _ in range(nbytes))).decode()

    def b64url(self, obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def _tokens(g: _Gen) -> dict[str, str]:
    j = lambda *p: "".join(p)  # noqa: E731 - split prefixes keep this file clean
    jwt = ".".join([
        g.b64url({"alg": "HS256", "typ": "JWT"}),
        g.b64url({"iss": "https://fleet-auth.edge.internal", "role": "service_role",
                  "sub": "maintenance-copilot", "iat": 1767225600, "exp": 2082758400}),
        g.s(43, B62 + "-_"),
    ])
    return {
        "aws_id": j("AK", "IA", g.s(16, B32)),
        "aws_secret": g.s(40, B62 + "/+"),
        "openai": j("sk", "-proj-", g.s(74, B62 + "_-")),
        "anthropic": j("sk", "-ant-", "api03-", g.s(93, B62 + "_-"), "AA"),
        "github": j("gh", "p_", g.s(36)),
        "gitlab": j("gl", "pat-", g.s(20)),
        "stripe": j("sk", "_live_", g.s(32)),
        "google": j("AI", "za", g.s(35, B62 + "-_")),
        "hf": j("hf", "_", g.s(34, UP + LO)),
        "npm": j("np", "m_", g.s(36)),
        "docker": j("dck", "r_pat_", g.s(27, B62 + "_-")),
        "slack_hook": j("https://hooks.", "slack.com/services/T", g.s(9, UP + DIG), "/B", g.s(9, UP + DIG), "/", g.s(24)),
        "sendgrid": j("S", "G.", g.s(22, B62 + "_-"), ".", g.s(43, B62 + "_-")),
        "db_password": g.s(20, B62 + "!#%"),
        "internal_token": g.s(40, B62),
        "jwt": jwt,
        "pk_body": "\n".join(textwrap.wrap(g.b64(1190), 64)),
        "gcp_pk_body": g.b64(1190),
        "gcp_key_id": g.s(40, "0123456789abcdef"),
    }


def _pem(kind: str, body: str) -> str:
    dashes = "-" * 5
    return f"{dashes}BEGIN {kind}{dashes}\n{body}\n{dashes}END {kind}{dashes}\n"


def _docker_image(path: Path, t: dict[str, str]) -> None:
    """Write a minimal `docker save`-style tarball: manifest.json + <layer>/layer.tar."""
    def tar_bytes(files: dict[str, str]) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, content in files.items():
                data = content.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = 1767225600
                tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    base_layer = tar_bytes({"etc/os-release": 'NAME="Rocky Linux"\nVERSION_ID="9.4"\n'})
    app_layer = tar_bytes({
        "app/config/registry.yaml": f"registry:\n  user: edge-ci\n  token: {t['docker']}\n",
        "app/config/notify.env": f"SENDGRID_KEY={t['sendgrid']}\n",
    })
    ids = ["3f9a1c0d2b7e4a51" * 4, "a71e0c9d55b24f08" * 4]
    manifest = [{"Config": "config.json", "RepoTags": ["edge-gateway:latest"],
                 "Layers": [f"{ids[0]}/layer.tar", f"{ids[1]}/layer.tar"]}]
    with tarfile.open(path, mode="w") as tf:
        for name, data in {
            "manifest.json": json.dumps(manifest).encode(),
            "config.json": b'{"architecture":"arm64","os":"linux"}',
            f"{ids[0]}/layer.tar": base_layer,
            f"{ids[1]}/layer.tar": app_layer,
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1767225600
            tf.addfile(info, io.BytesIO(data))


def _git_history(root: Path, t: dict[str, str]) -> bool:
    """Commit a token, then 'fix' it by deleting the file — the classic mistake."""
    if not shutil.which("git"):
        return False
    env_args = ["-c", "user.name=Fixture Bot", "-c", "user.email=fixtures@deadbolt.invalid",
                "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]

    def git(*a: str) -> None:
        subprocess.run(["git", *env_args, "-C", str(root), *a], check=True, capture_output=True)

    git("init", "-q")
    legacy = root / "config" / "legacy-ci.yaml"
    legacy.write_text(f"gitlab:\n  url: https://gitlab.edge.internal\n  token: {t['gitlab']}\n")
    git("add", "-A")
    git("commit", "-q", "-m", "wire up legacy CI mirror")
    legacy.unlink()
    git("add", "-A")
    git("commit", "-q", "-m", "remove secret (oops — still in history)")
    return True


def generate(out: Path, seed: int = 4471, with_git: bool = True) -> Path:
    g = _Gen(seed)
    t = _tokens(g)
    # Exclusive creation prevents accidental replacement and concurrent generators.
    out.mkdir(parents=True, exist_ok=False)
    files: dict[str, str] = {
        "README.md": textwrap.dedent("""\
            # edge-diagnostics (SYNTHETIC FIXTURE — every credential here is fake)
            Docs examples that must NOT be flagged:
              AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
              OPENAI_API_KEY=${OPENAI_API_KEY}
              password = "<your-password-here>"
        """),
        ".env": textwrap.dedent(f"""\
            AWS_ACCESS_KEY_ID={t['aws_id']}
            AWS_SECRET_ACCESS_KEY={t['aws_secret']}
            OPENAI_API_KEY={t['openai']}
            DATABASE_URL=postgresql://telemetry_rw:{t['db_password']}@pg-fleet.edge.internal:5432/telemetry
        """),
        "config/settings.py": textwrap.dedent(f"""\
            STRIPE_KEY = "{t['stripe']}"
            INTERNAL_API_TOKEN = "{t['internal_token']}"
            TIMEOUT_S = 30
        """),
        "config/gcp-service-account.json": json.dumps({
            "type": "service_" + "account", "project_id": "fleet-telemetry-prod",
            "private_key_id": t["gcp_key_id"],
            "private_key": _pem("PRIVATE KEY", t["gcp_pk_body"]),
            "client_email": "telemetry-writer@fleet-telemetry-prod.iam.gserviceaccount.com",
        }, indent=2),
        "deploy/firmware-signing.pem": _pem("RSA PRIVATE KEY", t["pk_body"]),
        ".cursor/mcp.json": json.dumps({"mcpServers": {
            "github": {
                "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": t["github"]},
            },
            "fs": {
                "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/"],
            },
            "shell": {
                "command": "uvx", "args": ["mcp-shell-server"], "autoApprove": ["*"],
            },
            "fleet-telemetry": {
                "url": "http://telemetry-gw.plant3.edge.internal:8080/mcp",
                "headers": {"Authorization": f"Bearer {t['jwt']}"},
            },
            "warehouse-db": {
                "command": "docker",
                "args": ["run", "-i", "--rm", "--network", "host", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                         "mcp/postgres:latest", "--api-key", t["anthropic"]],
            },
        }}, indent=2),
        "agents/maintenance-copilot.agent.yaml": textwrap.dedent("""\
            name: maintenance-copilot
            model: local/llama3.1-8b
            scopes: ["*"]
            oauth:
              scopes: ["https://www.googleapis.com/auth/cloud-platform"]
            tools: [read_telemetry, open_work_order, push_firmware]
        """),
        ".agent_cache/session-history.json": json.dumps({"messages": [
            {"role": "user", "content": "why is the inverter API failing?"},
            {"role": "assistant", "content": f"Retrying with key {t['anthropic']} ... ok"},
        ]}, indent=2),
        "prompts/diagnostics.prompt.md": textwrap.dedent(f"""\
            You are the plant-floor diagnostics copilot.
            When you need model weights, download with token {t['hf']}.
            Geocode sites with key {t['google']}.
        """),
        "ci-logs/build-4471.log": textwrap.dedent(f"""\
            [12:01:07] Step 4/9 : RUN npm publish
            [12:01:07] npm notice using NPM_TOKEN={t['npm']}
            [12:01:09] + echo "notify" && curl -X POST {t['slack_hook']}
        """),
        "terraform/alerts.tf": textwrap.dedent(f"""\
            resource "pagerduty_webhook" "fleet" {{
              slack_url = "{t['slack_hook']}"
            }}
        """),
    }
    for rel, content in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    (out / "artifacts").mkdir(exist_ok=True)
    _docker_image(out / "artifacts" / "edge-gateway.image.tar", t)
    if with_git:
        (out / "config").mkdir(exist_ok=True)
        _git_history(out, t)
    return out
