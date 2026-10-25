"""Detection patterns for secrets and PII.

Each entry maps a *category* to a list of compiled regular expressions.
A pattern may define a capture group; when it does, group 1 is treated as
the sensitive value (so a context-required pattern still reports only the
secret itself). Otherwise the whole match is the sensitive value.

Categories that count as *secrets* (they block publication) are listed in
``SECRET_CATEGORIES``; the remaining categories are PII / hygiene findings.

Fail-closed posture: where a shape is ambiguous the patterns lean toward
flagging — over-redacting a benign string is cheap, under-redacting a real
credential is a breach. Highly distinctive machine prefixes (``ghp_``,
``glpat-``, ``npm_``…) are matched *unanchored* — they do not occur inside
natural words, and anchoring would let %-encoding or adjacency
(``api_key%3Dghp_…``) smuggle a token past the scan.
"""

from __future__ import annotations

import re


def _rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Variable names that carry secrets, written four ways because env files,
# shell exports, YAML, JSON, dicts and JS literals all spell them
# differently. A name is sensitive when it contains a keyword
# (KEY/SECRET/TOKEN/PASSWORD/PASSWD/CREDENTIAL/AUTH) as:
#
#   1. an ALL-CAPS run anywhere           — MY_API_KEY, APIKEY, OAUTH_TOKEN
#   2. a component at the start or after  — api_key, secret, db_password,
#      ``_``, with digit/'s' tails and    token2, secrets, key_vault
#      ``_``-delimited continuations
#   3. a component ending the name        — apikey, apisecret, mytoken
#      (also catches monkey/hotkey/whiskey — accepted collateral)
#   4. a camelCase capitalized component  — apiKey, authToken, clientSecret
#
# ``keystore``, ``tokenize``, ``keyword``, ``author``, ``authority`` and
# ``monkeypatch`` stay out: the keyword must start the name, follow ``_``,
# end the name, or open a capitalized component.
ENV_NAME_PATTERN = (
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*?"
    r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)"
    r"[A-Za-z0-9_]*"
    r"|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*_)?"
    r"(?i:key|secret|token|password|passwd|credential|auth)"
    r"[0-9]*s?(?:_[A-Za-z0-9]+)*"
    r"|"
    r"[A-Za-z_][A-Za-z0-9_]*?"
    r"(?i:key|secret|token|password|passwd|credential|auth)s?"
    r"|"
    r"[A-Za-z_][A-Za-z0-9_]*[a-z0-9]"
    r"(?:Key|Secret|Token|Password|Passwd|Credential|Auth)"
    r"[A-Za-z0-9_]*"
    r")"
)


PATTERNS: dict[str, list[re.Pattern[str]]] = {
    # --- secrets -------------------------------------------------------
    "api_key": [
        # OpenAI-style keys: sk-..., sk-proj-... (sk-ant- lands here too).
        # `\b` stays: "sk-" occurs inside ordinary words (ask-...).
        _rx(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
        _rx(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        _rx(r"\brk_live_[A-Za-z0-9]{16,}\b"),
        # AWS access key id
        _rx(r"(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        # Google API key
        _rx(r"AIza[0-9A-Za-z_-]{35}\b"),
        # Slack tokens (xoxb/xoxa/xoxp/xoxr/xoxs) + app-level xapp-
        _rx(r"xox[baprs]-[0-9A-Za-z-]{10,}\b"),
        _rx(r"xapp-[0-9A-Za-z-]{10,}\b"),
        # GitLab PAT + scoped tokens (deploy/runner/agent/ci-build)
        _rx(r"glpat-[0-9A-Za-z_-]{16,}\b"),
        _rx(r"gl(?:dt|rt|cbt|agent)-[0-9A-Za-z_-]{16,}\b"),
        # npm access token
        _rx(r"npm_[0-9A-Za-z]{30,}\b"),
        # PyPI API token (pypi- + serialized macaroon)
        _rx(r"pypi-[0-9A-Za-z_-]{16,}\b"),
        # DigitalOcean personal access token
        _rx(r"dop_v1_[0-9A-Za-z]{20,}\b"),
        # SendGrid API key: SG.<~22>.<~43>
        _rx(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b"),
        # Square access tokens (sq0atp-) and CSP secrets (sq0csp-)
        _rx(r"sq0[a-z]{3}-[0-9A-Za-z_-]{20,}\b"),
        # Shopify access tokens (admin/custom/private/shared-secret)
        _rx(r"shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32,}\b"),
        # Google OAuth access token
        _rx(r"ya29\.[0-9A-Za-z_-]{10,}\b"),
        # Hugging Face access token
        _rx(r"hf_[0-9A-Za-z]{30,}\b"),
        # Stripe webhook-signing secret
        _rx(r"whsec_[0-9A-Za-z]{16,}\b"),
        # age encryption secret key
        _rx(r"AGE-SECRET-KEY-[0-9A-Z]{20,}\b"),
    ],
    "bearer_token": [
        # "Bearer <token>" — the auth scheme is case-insensitive
        # (RFC 6750) and shows up as "bearer:", "BEARER", tabs, "=".
        # One separator char is required so "BearerToken" stays a word.
        _rx(r"(?i)bearer[\s:=]+([A-Za-z0-9._~+/=-]{16,})"),
        # "Authorization: Basic <b64(user:pass)>" — only flagged in the
        # header context, and only when the value is not one plain
        # lowercase word ("basic authentication" prose stays out).
        _rx(
            r"(?i)authorization[\s]*:[\s]*basic[\s]+"
            r"((?![a-z]+\b)[A-Za-z0-9+/=]{8,})"
        ),
        # JWTs (header.payload.signature). Payload and signature can be
        # short — alg:none tokens end in a bare '.' — so the floor is
        # low; the eyJ header keeps false positives near zero.
        _rx(r"(eyJ[A-Za-z0-9_-]{1,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*)"),
    ],
    "github_token": [
        _rx(r"gh[pousr]_[A-Za-z0-9]{20,}\b"),
        _rx(r"github_pat_[A-Za-z0-9_]{22,}\b"),
    ],
    "private_key": [
        # Whole PEM block, header through footer — RSA/EC/DSA/OPENSSH/
        # ENCRYPTED variants and PGP's "... PRIVATE KEY BLOCK".
        _rx(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
            r".*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
            re.DOTALL,
        ),
        # Truncated/streamed PEM: header plus a base64 body that never
        # reaches a footer (partial pastes, clipped logs). Needs at
        # least one body line, so a bare header mention in docs is not
        # flagged. On a complete block this is a strict prefix of the
        # whole-block match and loses the overlap resolution to it.
        _rx(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
            r"[ \t]*\r?\n(?:[A-Za-z0-9+/=]+[ \t]*\r?\n?)+"
        ),
    ],
    "env_assignment": [
        # KEY=value / KEY: value assignments for sensitive-looking
        # variable names — `.env` lines, shell exports, YAML/dict
        # entries, quoted or bare names. See ENV_NAME_PATTERN. A leading
        # BOM char (\ufeff, kept in decoded UTF-16 text) is allowed at
        # line start so BOM-marked exports still match on line 1.
        # A *quoted* value is bounded at its closing quote when a JSON
        # continuation (`,`/`}`/`]`) or the line end follows —
        # `"api_key":"v","enabled":true` masks only `v` and leaves the
        # second property intact. A bare value still runs to end of
        # line, keeping `# comments` and shell tails redacted-in-line.
        _rx(
            r"(?m)^[\s\ufeff]*"
            # Shell declaration prefixes — ``export``/``local``/
            # ``readonly``/``typeset``/``env`` and flag-taking
            # ``declare -x`` — bind the same secret.
            r"(?:(?:export|local|readonly|typeset|env|declare)\s+"
            r"(?:-\w+\s+)*)?"
            # The name can hide behind a receiver — ``cfg.api_key``,
            # ``self.api_key``, ``config["api_key"]``: a hardcoded
            # secret is the same wherever it is bound.
            r"(?:"
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\[\s*[\"']?"
            + ENV_NAME_PATTERN + r"[\"']?\s*\]"
            r"|(?:[A-Za-z_]\w*\.)*\s*[\"']?" + ENV_NAME_PATTERN + r"[\"']?"
            r")"
            r"\s*[:=]\s*(?:"
            # An annotation head first — ``name: T = value``: the
            # ``T`` and its ``=`` belong to the match so a literal
            # default on a later line stays inside the span.
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
            r"(?:\s*\|\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)*\s*=\s*)?"
            # A parenthesized literal — ``key = ("x")``, possibly
            # wrapped across lines — needs its closer in the match:
            # ``("x", "y")`` must fall through to the bare arm so a
            # second secret in the tuple is never left behind.
            r"(?:\(\s*"
            r"(?:\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`)"
            r"\s*\)(?=[ \t]*[,}\]]|[ \t]*$)"
            r"|(?:\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`)"
            r"(?=[ \t]*[,}\]]|[ \t]*$)"
            r"|\S[^\n]*"
            r")"
        ),
        # JSON/dict entries anywhere on a line — `"token": "..."`,
        # `'api_key': '...'`, `{apiKey: `...`}` — including
        # JSON-escaped `\"token\":\"...\"`. The value must be a quoted
        # string: an unquoted value mid-line is prose, not an
        # assignment. Each quote kind gets its own alternative with an
        # escape-aware body (`\\.` is a value char, never a closer):
        # `\'` inside a `"`-quoted value and `\"` escapes can no longer
        # end the match early and leak the value's tail.
        _rx(
            r"(?<![\w'\"])\\?[\"']?" + ENV_NAME_PATTERN +
            r"\\?[\"']?\s*:\s*(?:"
            r"\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`"
            r"|\\\"(?:\\.|[^\"\\\r\n\\])*?\\\""
            r"|\\'(?:\\.|[^'\\\r\n\\])*?\\'"
            r")"
        ),
        # Keyword-argument secrets — ``f(api_key="x")``,
        # ``client(token = "x")``: a credential name bound to a
        # literal inside a call is the same hardcoded secret,
        # just without the line anchor. ``=`` only, and the
        # ``(?!=)`` guard keeps ``name==v`` comparisons and
        # ``=>`` arrows out. The value must be quoted — an
        # unquoted name mid-line is prose/code, not a secret.
        _rx(
            r"(?<![\w'\"])" + ENV_NAME_PATTERN +
            r"\s*=(?!=)\s*(?:"
            r"\(\s*"
            r"(?:\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`)"
            r"\s*\)(?=[ \t]*[,}\])]|[ \t]*$)"
            r"|\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`"
            r"|\\\"(?:\\.|[^\"\\\r\n\\])*?\\\""
            r"|\\'(?:\\.|[^'\\\r\n\\])*?\\'"
            r")"
        ),
        # Name-string call args — ``cfg.setdefault("api_key", "v")``,
        # ``d.get("token", "v")``: the credential name arrives as
        # the first call argument and the hardcoded secret as the
        # second. Bound to dict-style methods so ordinary
        # two-string calls stay out. The match has no ``=``/``:``
        # separator — the rewrite keeps everything through the
        # comma and masks only the value.
        _rx(
            r"(?<!\w)(?:setdefault|get|pop)\(\s*"
            r"\\?[\"']" + ENV_NAME_PATTERN + r"\\?[\"']\s*,\s*(?:"
            r"\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`"
            r")"
        ),
    ],
    "connection_uri": [
        # scheme://user:password@host — postgres, mysql, mongodb(+srv),
        # amqp, redis, and any other scheme smuggled through a custom
        # name. Group 1 is the userinfo (user:pass); a userinfo without
        # ':' carries no password and stays out.
        _rx(
            r"(?i)[a-z][a-z0-9+.-]{1,31}://"
            r"([^\s\"'`@/:]+:[^\s\"'`@/]*)@"
        ),
    ],
    "webhook_url": [
        # The URL itself is the credential.
        _rx(
            r"(?i)https://hooks\.slack\.com/services/"
            r"[0-9A-Za-z_-]+/[0-9A-Za-z_-]+/[0-9A-Za-z_-]+"
        ),
        _rx(
            r"(?i)https://(?:canary\.|ptb\.)?discord(?:app)?\.com/"
            r"api/webhooks/[0-9]+/[0-9A-Za-z._~-]+"
        ),
        _rx(
            r"(?i)https://[a-z0-9.-]*office\.com/webhookb2/"
            r"[0-9A-Za-z@/._-]+"
        ),
    ],
    "devin_pairing_code": [
        # Pairing codes only count with explicit context — group 1 is the code.
        _rx(
            r"(?i)(?:pairing|pair)[ -]?code\s*[:=]?\s*"
            r"([A-Z0-9]{4}(?:-[A-Z0-9]{4}){1,3})"
        ),
    ],
    # --- PII / hygiene --------------------------------------------------
    "email": [
        _rx(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ],
    "absolute_path": [
        # Windows user paths: C:\Users\<name>\...
        _rx(r"\b[A-Za-z]:\\Users\\[^\s\"'<>|]+"),
        # POSIX home paths: /home/<name>/... and macOS /Users/<name>/...
        _rx(r"(?<![\w/.-])/(?:home|Users)/[^\s\"'<>|]+"),
    ],
}

SECRET_CATEGORIES = frozenset(
    {
        "api_key",
        "bearer_token",
        "github_token",
        "private_key",
        "env_assignment",
        "connection_uri",
        "webhook_url",
        "devin_pairing_code",
    }
)

PII_CATEGORIES = frozenset(PATTERNS) - SECRET_CATEGORIES

# Pattern names used when reporting, one per regex (index-based fallback).
_PATTERN_NAMES: dict[str, list[str]] = {
    "api_key": [
        "openai_key",
        "stripe_live_key",
        "stripe_restricted_key",
        "aws_access_key_id",
        "google_api_key",
        "slack_token",
        "slack_app_token",
        "gitlab_pat",
        "gitlab_scoped_token",
        "npm_token",
        "pypi_token",
        "digitalocean_pat",
        "sendgrid_key",
        "square_token",
        "shopify_token",
        "google_oauth_token",
        "huggingface_token",
        "stripe_webhook_secret",
        "age_secret_key",
    ],
    "bearer_token": ["bearer_header", "basic_auth_header", "jwt"],
    "github_token": ["github_token", "github_fine_grained_pat"],
    "private_key": ["pem_private_key", "pem_private_key_unterminated"],
    "env_assignment": ["env_assignment", "env_assignment_json"],
    "connection_uri": ["uri_userinfo"],
    "webhook_url": ["slack_webhook_url", "discord_webhook_url", "office365_webhook_url"],
    "devin_pairing_code": ["devin_pairing_code"],
    "email": ["email"],
    "absolute_path": ["windows_user_path", "posix_home_path"],
}


def pattern_name(category: str, index: int) -> str:
    """Human-readable name for ``PATTERNS[category][index]``."""
    names = _PATTERN_NAMES.get(category, [])
    if 0 <= index < len(names):
        return names[index]
    return f"{category}[{index}]"


def sensitive_match(match: re.Match[str]) -> str:
    """Return the sensitive value of a regex match (group 1 if present).

    A leading ``\\ufeff`` is stripped: BOM-marked decodes keep the mark
    in the text (so re-encoding stays byte-identical), but it is not
    secret material — the same ``KEY=value`` must fingerprint alike in
    UTF-8 and BOM'd UTF-16 files.
    """
    if match.lastindex:
        return match.group(1).lstrip("\ufeff")
    return match.group(0).lstrip("\ufeff")
