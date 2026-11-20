"""Secret detection rules.

Each rule carries more than a regex: it also declares what the credential is
*allowed to do* (authority), whether it can run up a bill (spend), and the
human revocation runbook. That metadata is what powers deterministic
blast-radius triage — no network calls, no LLM required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Authority, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    provider: str
    pattern: re.Pattern[str]
    keywords: tuple[str, ...]
    authority: Authority
    scope: str
    revoke: tuple[str, ...]
    severity: Severity = Severity.HIGH
    spend: bool = False  # can an attacker burn money with it?
    group: int = 0  # regex group holding the secret value
    min_entropy: float = 0.0
    tags: tuple[str, ...] = field(default_factory=tuple)


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


RULES: tuple[Rule, ...] = (
    # ---------------------------------------------------------------- cloud
    Rule(
        id="DB-AWS-001",
        title="AWS access key ID",
        provider="aws",
        pattern=_r(r"\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16})\b"),
        keywords=("akia", "asia", "abia", "acca", "a3t"),
        authority=Authority.DEPLOY,
        scope="IAM principal — real reach depends on attached policies; assume deploy until reviewed",
        spend=True,
        group=1,
        revoke=(
            "aws iam list-access-keys --user-name <owner>  # confirm owner of the key ID",
            "aws iam update-access-key --access-key-id <KEY_ID> --status Inactive",
            "Review CloudTrail for the key ID since first exposure (LookupAttributes AccessKeyId)",
            "aws iam delete-access-key --access-key-id <KEY_ID> after replacement is live",
        ),
    ),
    Rule(
        id="DB-AWS-002",
        title="AWS secret access key",
        provider="aws",
        pattern=_r(
            r"(?i)aws[_\-\s.]{0,4}(?:secret|sk)[a-z_\-\s.]{0,20}[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        keywords=("aws",),
        authority=Authority.DEPLOY,
        scope="Pairs with an access key ID; together they act as the IAM principal",
        spend=True,
        group=1,
        severity=Severity.CRITICAL,
        min_entropy=3.5,
        revoke=(
            "Identify the paired access key ID in the same file/commit",
            "Deactivate, rotate and audit exactly as for DB-AWS-001",
        ),
    ),
    Rule(
        id="DB-GCP-001",
        title="GCP service-account private key",
        provider="gcp",
        pattern=_r(r"\"type\"\s*:\s*\"service_account\""),
        keywords=("service_account",),
        authority=Authority.DEPLOY,
        scope="Service-account identity; reach = IAM roles bound in the project/org",
        spend=True,
        severity=Severity.CRITICAL,
        revoke=(
            "gcloud iam service-accounts keys list --iam-account <SA_EMAIL>",
            "gcloud iam service-accounts keys disable <KEY_ID> --iam-account <SA_EMAIL>",
            "Prefer Workload Identity Federation — remove the need for exported JSON keys",
        ),
    ),
    Rule(
        id="DB-GCP-002",
        title="Google API key (Gemini / Maps / Cloud APIs)",
        provider="google",
        pattern=_r(r"\b(AIza[0-9A-Za-z\-_]{35})(?![0-9A-Za-z\-_])"),
        keywords=("aiza",),
        authority=Authority.READ,
        scope="Billable API calls for every API the key is not restricted from (incl. Gemini)",
        spend=True,
        group=1,
        revoke=(
            "Cloud Console → APIs & Services → Credentials → regenerate or delete the key",
            "Add API + application restrictions to the replacement key",
            "Check billing reports for anomalous usage since exposure",
        ),
    ),
    Rule(
        id="DB-AZ-001",
        title="Azure storage account key",
        provider="azure",
        pattern=_r(r"AccountKey=([A-Za-z0-9+/]{86}==)"),
        keywords=("accountkey=",),
        authority=Authority.ADMIN,
        scope="Full control of every container, queue and table in the storage account",
        group=1,
        severity=Severity.CRITICAL,
        revoke=("az storage account keys renew --account-name <NAME> --key primary",),
    ),
    # ----------------------------------------------------------- AI / LLM
    Rule(
        id="DB-ANT-001",
        title="Anthropic API key",
        provider="anthropic",
        pattern=_r(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,120})"),
        keywords=("sk-ant-",),
        authority=Authority.WRITE,
        scope="Model inference billed to the org; admin keys can manage the org",
        spend=True,
        group=1,
        severity=Severity.CRITICAL,
        revoke=("Claude Console → API keys → disable the key, then issue a scoped replacement",),
        tags=("ai",),
    ),
    Rule(
        id="DB-OAI-001",
        title="OpenAI API key",
        provider="openai",
        pattern=_r(
            r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,200}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9_\-])"
        ),
        keywords=("sk-proj-", "sk-svcacct-", "sk-admin-", "t3blbkfj"),
        authority=Authority.WRITE,
        scope="Model inference billed to the project; admin keys manage the org",
        spend=True,
        group=1,
        severity=Severity.CRITICAL,
        revoke=("platform.openai.com → API keys → revoke; check Usage for spend since exposure",),
        tags=("ai",),
    ),
    Rule(
        id="DB-HF-001",
        title="Hugging Face access token",
        provider="huggingface",
        pattern=_r(r"\b(hf_[A-Za-z]{34})\b"),
        keywords=("hf_",),
        authority=Authority.WRITE,
        scope="Read/write to the owner's models, datasets and Spaces depending on token role",
        group=1,
        revoke=("huggingface.co/settings/tokens → invalidate and refresh",),
        tags=("ai",),
    ),
    # --------------------------------------------------- source & supply chain
    Rule(
        id="DB-GH-001",
        title="GitHub token",
        provider="github",
        pattern=_r(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
        authority=Authority.WRITE,
        scope="Repository read/write per token scopes; workflow scope enables CI code execution",
        group=1,
        severity=Severity.CRITICAL,
        revoke=(
            "github.com/settings/tokens → delete the token (or org admin: revoke via credential audit)",
            "Review the org audit log for actions taken with the token",
        ),
    ),
    Rule(
        id="DB-GL-001",
        title="GitLab personal access token",
        provider="gitlab",
        pattern=_r(r"\b(glpat-[A-Za-z0-9\-_]{20})\b"),
        keywords=("glpat-",),
        authority=Authority.WRITE,
        scope="Project/repo access per token scopes",
        group=1,
        revoke=("GitLab → Preferences → Access Tokens → revoke",),
    ),
    Rule(
        id="DB-NPM-001",
        title="npm access token",
        provider="npm",
        pattern=_r(r"\b(npm_[A-Za-z0-9]{36})\b"),
        keywords=("npm_",),
        authority=Authority.DEPLOY,
        scope="Publish packages as the owner — direct software supply-chain authority",
        group=1,
        severity=Severity.CRITICAL,
        revoke=("npm token revoke <id>; audit recent publishes with `npm view <pkg> time`",),
    ),
    Rule(
        id="DB-PYPI-001",
        title="PyPI upload token",
        provider="pypi",
        pattern=_r(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})"),
        keywords=("pypi-ageichlwas5vcmc",),
        authority=Authority.DEPLOY,
        scope="Upload releases to the owner's PyPI projects — supply-chain authority",
        group=1,
        severity=Severity.CRITICAL,
        revoke=("pypi.org → Account settings → API tokens → remove; prefer Trusted Publishing",),
    ),
    Rule(
        id="DB-DOCKER-001",
        title="Docker Hub personal access token",
        provider="docker",
        pattern=_r(r"\b(dckr_pat_[A-Za-z0-9_\-]{27})\b"),
        keywords=("dckr_pat_",),
        authority=Authority.DEPLOY,
        scope="Push images as the owner — anything that pulls :latest runs attacker code",
        group=1,
        revoke=("hub.docker.com → Account settings → Security → delete token",),
    ),
    # ------------------------------------------------------- SaaS / payments
    Rule(
        id="DB-STRIPE-001",
        title="Stripe live secret key",
        provider="stripe",
        pattern=_r(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b"),
        keywords=("sk_live_", "rk_live_"),
        authority=Authority.ADMIN,
        scope="Live payments API: charges, refunds, payouts, customer PII",
        spend=True,
        group=1,
        severity=Severity.CRITICAL,
        revoke=("Stripe Dashboard → Developers → API keys → roll key (set expiry on the old one to now)",),
    ),
    Rule(
        id="DB-SLACK-001",
        title="Slack token",
        provider="slack",
        pattern=_r(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,72})\b"),
        keywords=("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"),
        authority=Authority.WRITE,
        scope="Read/post messages and files per granted OAuth scopes",
        group=1,
        revoke=("api.slack.com/apps → OAuth & Permissions → revoke; or call auth.revoke",),
    ),
    Rule(
        id="DB-SLACK-002",
        title="Slack incoming webhook",
        provider="slack",
        pattern=_r(r"(https://hooks\.slack\.com/services/T[A-Z0-9]{6,12}/B[A-Z0-9]{6,12}/[A-Za-z0-9]{20,32})"),
        keywords=("hooks.slack.com",),
        authority=Authority.WRITE,
        scope="Post arbitrary messages into one channel (phishing from a trusted bot)",
        group=1,
        severity=Severity.MEDIUM,
        revoke=("Slack app config → Incoming Webhooks → remove and regenerate",),
    ),
    Rule(
        id="DB-SG-001",
        title="SendGrid API key",
        provider="sendgrid",
        pattern=_r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
        keywords=("sg.",),
        authority=Authority.WRITE,
        scope="Send email as your verified domains",
        spend=True,
        group=1,
        revoke=("SendGrid → Settings → API Keys → delete",),
    ),
    # --------------------------------------------------------- crypto material
    Rule(
        id="DB-PK-001",
        title="Private key",
        provider="pki",
        pattern=_r(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----"),
        keywords=("private key",),
        authority=Authority.ADMIN,
        scope="Identity material: SSH host/user, TLS server, or code/firmware signing key",
        severity=Severity.CRITICAL,
        revoke=(
            "Identify what trusts the public half (authorized_keys, TLS cert, signing trust store)",
            "Generate a new keypair in an HSM/KMS where possible; revoke the cert / remove the pubkey",
            "If it signs firmware or releases: treat every artifact signed since exposure as suspect",
        ),
    ),
    Rule(
        id="DB-DBURL-001",
        title="Database URL with embedded credentials",
        provider="database",
        pattern=_r(
            r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^\s:/@\"'<>]{1,64}:([^\s@\"'<>]{4,128})@[^\s\"'<>]{3,})"
        ),
        keywords=("://",),
        authority=Authority.WRITE,
        scope="Direct data-plane access to the database as that user",
        group=2,
        min_entropy=2.5,
        revoke=("ALTER USER ... PASSWORD / rotate in the secrets manager; restrict network ingress",),
    ),
    Rule(
        id="DB-JWT-001",
        title="JSON Web Token",
        provider="jwt",
        pattern=_r(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,})"),
        keywords=("eyj",),
        authority=Authority.UNKNOWN,  # refined from decoded claims in blast.py
        scope="Bearer token — authority comes from its claims (role / scope / exp)",
        group=1,
        severity=Severity.MEDIUM,
        revoke=(
            "Rotate the signing secret/key if the token is long-lived or a service role",
            "Revoke the session/refresh token at the issuer",
        ),
    ),
)

# Generic: secret-ish variable name assigned a high-entropy literal.
GENERIC_RULE = Rule(
    id="DB-GEN-001",
    title="Hardcoded credential (generic)",
    provider="generic",
    # anchored on the keyword itself so the regex engine skips quickly through ordinary text
    pattern=_r(
        r"(?i)(?:api[_\-]?key|apikey|secret|token|passw(?:or)?d|pwd|auth[_\-]?key|private[_\-]?key|access[_\-]?key|credential)"
        r"[a-z0-9_.\-]{0,24}[\"']?[ \t]*(?::|=|:=|=>)[ \t]*[\"']?([A-Za-z0-9_\-+/=.~!@#$%^&*]{12,200})"
    ),
    group=1,
    keywords=("key", "secret", "token", "passw", "pwd", "credential"),
    authority=Authority.UNKNOWN,
    scope="Unknown service — identify the consumer of this value",
    severity=Severity.MEDIUM,
    min_entropy=3.6,
    revoke=("Find the system that accepts this value, rotate it there, move it to a secrets manager",),
)

ALL_RULES: tuple[Rule, ...] = RULES + (GENERIC_RULE,)
RULES_BY_ID = {r.id: r for r in ALL_RULES}

# Values that are documentation examples or obvious placeholders.
KNOWN_EXAMPLES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
)

_PLACEHOLDER = re.compile(
    r"(?ix)^(?:"
    r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"  # ${VAR} / $VAR
    r"|\{\{.*\}\}"  # {{ template }}
    r"|<[^>]+>"  # <your-key>
    r"|%\([^)]+\)s"
    r"|(?:x+|\*+|\.+|-+|0+)"
    r")$"
)
_PLACEHOLDER_WORDS = (
    "example", "changeme", "change_me", "placeholder", "your_", "your-", "yourkey",
    "dummy", "redacted", "xxxxxx", "insert", "replace", "sample", "notreal", "todo",
    "process.env", "os.environ", "getenv", "secretsmanager", "vault:", "env(",
)


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'")
    if v in KNOWN_EXAMPLES:
        return True
    if _PLACEHOLDER.match(v):
        return True
    low = v.lower()
    return any(w in low for w in _PLACEHOLDER_WORDS)
