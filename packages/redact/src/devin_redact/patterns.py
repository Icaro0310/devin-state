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
    r"(?i:key|secret|token|password|passwd|credential|auth|pw)s?"
    r"|"
    r"[A-Za-z_][A-Za-z0-9_]*[a-z0-9]"
    r"(?:Key|Secret|Token|Password|Passwd|Credential|Auth)"
    r"[A-Za-z0-9_]*"
    r"|"
    # ``PASS``/``PWD``/``PW``/``PASSPHRASE`` only bind as a whole
    # name or after an underscore — ``db_pass`` and ``ftp_pwd`` are
    # credentials but ``compass`` and ``bypass`` are not.
    r"(?:[A-Za-z_][A-Za-z0-9_]*_)?"
    r"(?i:pass|pwd|pw|sshpass|passphrase|passcode|userpass)[0-9]*s?"
    r")"
)

# Dotted property-path names — Java system properties, INI keys,
# ``ini_set``/``setProperty`` targets: ``db.password``,
# ``spring.datasource.api-key`` (``-`` allowed inside segments),
# ``session.secret``. The credential word keeps its boundary rules
# so ``db.compass`` stays out; the name must still carry a real
# separator segment or a credential suffix.
DOTTED_NAME_PATTERN = (
    r"(?:"
    r"[A-Za-z_][\w.-]*?"
    r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[\w.-]*"
    r"|"
    r"(?:[A-Za-z_][\w.-]*?[._-])?"
    r"(?i:key|secret|token|password|passwd|credential|auth)"
    r"[0-9]*s?(?:[._-][A-Za-z0-9]+)*"
    r"|"
    r"[A-Za-z_][\w.-]*?"
    r"(?i:key|secret|token|password|passwd|credential|auth)s?"
    r"|"
    r"[A-Za-z_][\w.-]*[a-z0-9]"
    r"(?:Key|Secret|Token|Password|Passwd|Credential|Auth)[\w.-]*"
    r"|"
    r"(?:[A-Za-z_][\w.-]*?[._-])?"
    r"(?i:pass|pwd|passphrase|passcode|userpass)[0-9]*s?"
    r")"
)


# Credential tuples — ``auth=("user", "pw")`` /
# ``session.auth = ("u", "p")`` (requests/httpx basic-auth shape):
# only an auth-declaring name makes the second literal a password —
# ``_TOKENS = ("a", "b")`` stays a constant. Group 1 keeps its
# quotes so the tuple still parses. Named at module level so the
# engine can exempt it from the code-assignment guard (see
# ``GUARD_EXEMPT_PATTERNS``).
_CRED_TUPLE_RX = _rx(
    r"(?<![\w])(?:[A-Za-z_]\w*\.)*\s*"
    r"(?i:auth|authn|creds?|credentials|userpass)"
    r"[ \t]*=[ \t]*\(\s*"
    r"(?:\"(?:\\.|[^\"\\\r\n])*?\"|'(?:\\.|[^'\\\r\n])*?')"
    r"\s*,\s*"
    r"(\"(?:\\.|[^\"\\\r\n])*?\"|'(?:\\.|[^'\\\r\n])*?')"
)

# LDAP slapd.conf — ``rootpw x``, ``olcRootPW: x`` and
# ``olcRootPW={SSHA}…``; whitespace, ``:`` and ``=`` all appear in
# the wild. The ``{SSHA}`` scheme prefix looks like a container to
# the code guard, so the arm is exempt (``GUARD_EXEMPT_PATTERNS``).
_LDAP_ROOTPW_RX = _rx(
    r"(?im)^[ \t]*(?:olcRootPW|rootpw)[ \t:=]+"
    r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
)

# ``.pgpass`` five-field rows — ``host:port:db:user:password``;
# ``\:`` and ``\\`` escapes are field content, not separators, so
# each field is a run of escapes-or-non-colons. Gated to the
# filename via ``FILE_GATED_PATTERNS`` (the ext check is
# ``endswith``-based so the dotfile basename matches).
_PGPASS_RX = _rx(
    r"(?im)^[ \t]*(?:\\.|[^:\\\r\n])*"
    r"(?::(?:\\.|[^:\\\r\n])*){3}:((?:\\.|[^\s:\\])+)"
)

# One CLI token: a double/single-quoted string (escape-aware) or a
# bare word. Shared by arms that take a positional secret.
_CLITOK = (
    r"(?:\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
)

# Mail-client rc files — ``password x`` / ``password "x"`` is a
# directive in msmtprc/esmtprc/fetchmailrc but plain prose
# elsewhere, so the arm is gated to those filenames
# (``FILE_GATED_PATTERNS``). Unanchored: fetchmailrc carries
# ``poll h user u password "x"`` mid-line.
_MAILPASS_RX = _rx(
    r"(?i)\bpassword[ \t]+"
    r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'"
    r"|(?:\\.|[^\s;\\#])+)"
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
        # The lowercase-word guard must stay case-sensitive under the
        # outer (?i), so it is scoped with (?-i:...) — otherwise a
        # base64 blob of only letters looks like a word and escapes.
        _rx(
            r"(?i)authorization[\s]*:[\s]*basic[\s]+"
            r"((?!(?-i:[a-z]+\b))[A-Za-z0-9+/=]{8,})"
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
            # ``readonly``/``typeset``/``env``/``set`` and flag-taking
            # ``declare -x`` — bind the same secret. Case-insensitive
            # so Dockerfile ``ENV``/``ARG KEY=v`` and cmd ``SET``
            # match the same anchor. A list bullet (``-``/``*``/``+``)
            # or comment opener (``#``/``//``/``<!--``/``;``) before
            # the name hides the same bind — docker-compose
            # ``environment:`` lists and commented-out credentials.
            r"(?:(?i:export|local|readonly|typeset|env|declare|arg|set"
            # Typed-language declaration modifiers — ``const``,
            # ``let``/``var``/``val``, access/storage keywords and the
            # common builtin type words in ``const String K = "v"`` —
            # repeat so ``private static final String`` is one prefix.
            r"|const|let|var|val|static|final|public|private|protected"
            r"|internal|dim|my|our|mut|volatile|unsigned|signed|long"
            r"|short|char|int|float|double|bool|string|auto|def|fun"
            r"|function|struct|enum|class|interface|type|typename|ref"
            r"|String|str)"
            r"\s+|(?:-\w+\s+)|(?:[*+-]|#+|//+|<!--|;)\s*)*"
            # The name can hide behind a receiver — ``cfg.api_key``,
            # ``self.api_key``, ``config["api_key"]`` — or an
            # env-subscript with a sigil or brace —
            # ``$ENV{API_KEY}``, ``$_ENV["API_KEY"]``,
            # ``ENV['KEY']``: a hardcoded secret is the same
            # wherever it is bound.
            r"(?:"
            r"\$?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*[\[{]\s*[\"']?"
            + ENV_NAME_PATTERN + r"[\"']?\s*[\]}]"
            r"|(?:[A-Za-z_]\w*\.)*\s*[\"']?" + ENV_NAME_PATTERN + r"[\"']?"
            r")"
            # A ``\``-continued separator — ``key = \<newline>"v"`` —
            # puts the literal on the next physical line. Makefile
            # and BSD-make operators join ``=``/``:`` — ``:=``,
            # ``?=``, ``+=``, ``::=`` — as a single separator so the
            # operator survives the mask (``KEY := <tag>`` still
            # parses).
            r"\s*(?:::|[:+?])?[ \t]*[:=][ \t]*(?:\\\r?\n[ \t]*)*\s*(?:"
            # An annotation head first — ``name: T = value``: the
            # ``T`` and its ``=`` belong to the match so a literal
            # default on a later line stays inside the span. Rust
            # reference types lead with ``&``/lifetimes/``mut``
            # (``const K: &str = "v"``, ``&'a mut str``).
            r"(?:(?:&[ \t]*(?:'[A-Za-z_]\w*)?[ \t]*(?:mut[ \t]+)?)+)?"
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
            r"(?:\s*\|\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)*\s*=\s*)?"
            # A parenthesized literal — ``key = ("x")``, possibly
            # wrapped across lines or implicit-concatenated
            # ``("a" "b")`` — needs its closer in the match:
            # ``("x", "y")`` must fall through to the bare arm so a
            # second secret in the tuple is never left behind.
            r"(?:\(\s*"
            r"(?:\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`)"
            r"(?:(?:\s|\\[ \t]*\r?\n[ \t]*)*"
            r"(?:\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`))*"
            r"\s*\)(?=[ \t]*[,}\]]|[ \t]*$)"
            r"|(?:\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`)"
            # Implicit ``\``-continuation concatenation —
            # ``"a" \<newline> "b"`` — extends the literal.
            r"(?:[ \t]*\\\r?\n[ \t]*"
            r"(?:\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`))*"
            r"(?=[ \t]*[,}\]]|[ \t]*$)"
            # YAML block scalar — ``key: |`` / ``key: >`` puts the
            # value on the following indented lines; masking only
            # the indicator leaves the secret behind. A YAML tag
            # (``!vault``…) may sit between ``:`` and the bar —
            # ``api_key: !vault |`` hides ciphertext, not text.
            r"|(?:!\S+[ \t]+)?[|>][-+]?[ \t]*(?:\r?\n[ \t]+\S[^\n]*)+"
            # Bare value runs to end of logical line — a ``\``
            # continuation keeps the tail inside the mask.
            r"|\S(?:[^\n\\]|\\\r?\n)*"
            r")"
        ),
        # Dockerfile ``ENV KEY value`` / ``ARG KEY value`` — the
        # legacy whitespace separator (still parsed by the builder)
        # carries no ``=``, so it needs its own line-anchored arm.
        # fish ``set -x K v``/``set -gx K v``, csh ``setenv K v``
        # and ``launchctl setenv K v`` share the shape, with an
        # optional flag run between the builtin and the name.
        _rx(
            r"(?mi)^[\s\ufeff]*"
            r"(?:(?i:env|arg|set|setenv|setx|launchctl[ \t]+setenv))"
            r"(?:[ \t]+[-/][a-zA-Z]+)*[ \t]+"
            + ENV_NAME_PATTERN +
            r"(?:[ \t]*=[ \t]*|[ \t]+)(?:"
            r"\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`"
            r"|\S(?:[^\n\\]|\\\r?\n)*"
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
            # ``:=`` joins ``:`` here too — Go short-var declarations
            # (``apiKey := "v"``) carry the same bound literal.
            r"\\?[\"']?\s*:[ \t]*=?\s*(?:"
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
            r"(?<!\w)(?:setdefault|get|pop|putenv|setenv|getenv"
            r"|define)\(\s*"
            r"\\?[\"'](?:" + ENV_NAME_PATTERN + r"|"
            + DOTTED_NAME_PATTERN + r")\\?[\"']\s*,\s*(?:"
            r"\"\"\"(?:\\.|[^\"\\])*?\"\"\""
            r"|'''(?:\\.|[^'\\])*?'''"
            r"|\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`"
            r")"
        ),
        # Name-string call arg in any position — a quoted
        # credential-shaped argument followed by a quoted literal:
        # ``config.set("sec", "api_key", "v")`` or the two-arg
        # ``f("API_KEY", "v")`` / ``SetEnvironmentVariable("K","v")``
        # where the name opens the call. Group 1 is the value
        # literal (quotes stay inside so the engine masks inside
        # them).
        _rx(
            r"[(,]\s*[\"'](?:" + ENV_NAME_PATTERN + r"|"
            + DOTTED_NAME_PATTERN + r")[\"']\s*,\s*"
            r"(\"(?:\\.|[^\"\\\r\n])*?\"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`)"
        ),
        # Single-arg credential setter — ``cfg.set_key("v")``,
        # ``client.withToken("v")``, ``api.setPassword('v')``: the
        # method name declares the secret, the literal is the value.
        _rx(
            r"(?i)\.(?:set|with|use|add)[\w_]*"
            r"(?:key|token|secret|password|passwd|credential|auth)"
            r"[\w_]*\(\s*(\"(?:\\.|[^\"\\\r\n])+\"|'(?:\\.|[^'\\\r\n])+')"
        ),
        # C preprocessor — ``#define API_KEY "v"``; quoted only so
        # constants like ``AUTH_TIMEOUT 30`` stay out.
        _rx(
            r"(?im)^[ \t]*#[ \t]*define[ \t]+" + ENV_NAME_PATTERN +
            r"[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*')"
        ),
        # Emacs Lisp — ``(setq api-key "v")``; hyphenated names and
        # the ``*earmuff*`` convention for special variables.
        _rx(
            r"(?i)\((?:setq|defvar|defconst|defcustom|setopt)[ \t]+"
            r"[\w*-]*(?:key|token|secret|password|passwd|credential"
            r"|auth)[\w*-]*[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*')"
        ),
        # plist XML pair — ``<key>api_key</key><string>v</string>``
        # (``<data>`` is the base64 carrier); group 1 is the element
        # text, non-empty so ``<string/>`` slots stay untouched.
        _rx(
            r"(?i)<key>[ \t]*" + ENV_NAME_PATTERN +
            r"[ \t]*</key>[ \t]*<(?:string|data)>([^<]+)</(?:string|data)>"
        ),
        # URL query secrets — ``?api_key=v``, ``&token=v``,
        # ``;secret=v`` — live mid-line in logged URLs, so no line
        # anchor. ``:`` covers the .npmrc/.yarnrc host-scoped form
        # ``//registry.io/:_authToken=v``. The value stops at the
        # next param, fragment or whitespace; ``#`` doubles as a
        # separator (fragment-style params) — a ``#api_key=v`` in a
        # comment is exactly the leak it should mask.
        _rx(
            r"[?&;#:]" + ENV_NAME_PATTERN + r"=[^\s&#]+"
        ),
        # Terraform/HCL variable defaults — the credential name is
        # the block's *argument* (``variable "api_key"``) and the
        # secret sits in ``default = "…"``, so no mid-line arm can
        # see the pair. ``[^}]`` keeps the bridge inside the block.
        _rx(
            r"(?i)variable[ \t]+\\?[\"']" + ENV_NAME_PATTERN +
            r"\\?[\"'][ \t]*\{[^}]*?default[ \t]*=[ \t]*(?:"
            r"\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r")"
        ),
        # .netrc / .authinfo — ``machine h login u password p``:
        # positional keywords, no ``=``, and real files usually wrap
        # the tokens across lines (``\s`` covers the newlines). A
        # ``default`` entry has no host name. Entries are
        # line-anchored so "the default login uses password x" prose
        # stays out. Group 1 is the password so the fingerprint
        # covers the secret, not the context.
        _rx(
            r"(?im)^[ \t]*(?:machine\s+\S+|default)\s+login\s+\S+\s+"
            r"(?:password|account)\s+(\S+)"
        ),
        # Escaped property separators — Java ``.properties`` allows
        # ``\=``, ``\:``, ``\u003d``; prose never spells
        # them. Group 1 is the value.
        _rx(
            r"(?<!\w)" + ENV_NAME_PATTERN +
            r"[ \t]*(?:\\u003[daDA]|\\[:=])[ \t]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # CLI credential flags — ``sshpass -p``, ``curl -u u:p`` /
        # ``--proxy-user``, ``redis-cli -a``, ``ldap* -w``,
        # ``mosquitto_* -P``; httpie's ``http METHOD url -a u:p``
        # needs a method gap before the flag. Group 1 is the
        # token, quoted or bare.
        _rx(
            r"(?i)\b(?:sshpass[ \t]+-p|(?:curl|wget|httpie?|fetch)\S*"
            r"[ \t]+(?:-u|--user|-U|--proxy-user)|redis-cli[ \t]+-a"
            r"|ldap\w+\b[^\n]*?[ \t]-w|mosquitto_\w+[ \t]+-P"
            r"|https?[ \t]+(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS"
            r"|get|post)\b[^\n]*?[ \t](?:-a|--auth))[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # mysql family ``-p<pass>`` — the value rides attached and
        # may follow other flags (``-u root -psecret``). Kept
        # case-sensitive: ``-P`` is the *port* flag.
        _rx(
            r"\b(?:mysql|mysqldump|mariadb|mysqladmin|mysqlcheck)"
            r"\w*\b[^\n]*?\s-p(\S+)"
        ),
        # htpasswd/mosquitto_passwd batch mode — ``-b file user
        # pass``, combined flag clusters (``-cb``, ``-mb``) and
        # display mode (``-nb user pass``); 1–3 positionals follow
        # the flags, the password is last.
        _rx(
            r"(?i)\b(?:htpasswd|mosquitto_passwd)[ \t]+-\w*b\w*"
            r"(?:[ \t]+\S+){1,3}[ \t]+((?:\\.|[^\s\\|&;])+)"
        ),
        # Long option carrying the secret as the next argument —
        # ``--password pw``, ``--http-password pw``, ``--api-key k``,
        # ``--client-secret s``, ``--auth-token t``. The flag must
        # *end* in the credential word, so ``--password-file f`` and
        # ``--token-type t`` stay out.
        _rx(
            r"(?i)--[\w-]*(?:password|passwd|passphrase|pass|secret"
            r"|token|api[-_]?key|access[-_]?key|client[-_]?secret"
            r"|auth[-_]?token|bearer)[ \t=]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # Tool flags where the secret rides a short option or a
        # named setter — docker/podman ``login -p``, zip/unzip ``-P``
        # (uppercase, case matters), 7z ``-p``, and
        # ``aws configure set <name> <value>``.
        _rx(
            r"\b(?:(?:docker|podman|skopeo|buildah|oras"
            r"|podman-remote)[ \t]+login|crane[ \t]+(?:auth[ \t]+)?"
            r"login|helm[ \t]+registry[ \t]+login)\b"
            r"[^\n]*?[ \t]-p[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(r"\b(?:zip|unzip)\b[^\n]*?[ \t]-P[ \t=]*(\S+)"),
        _rx(r"\b7z[ \t]+\S+[ \t]+-p(\S+)"),
        _rx(
            r"(?i)\baws[ \t]+configure[ \t]+set[ \t]+"
            r"\S*(?:key|secret|token)\S*[ \t]+(\S+)"
        ),
        _rx(
            r"(?i)\b(?:poetry|pip|npm|gem|bundle|git)[ \t]+config(?:"
            r"[ \t]+set|(?:[ \t]+--?\w+)*)?[ \t]+"
            r"\S*(?:key|secret|token|pass\w*)\S*[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # Windows ``net user <name> <password>`` — the password is a
        # bare positional; ``(?!/)`` keeps ``/add``-style switches
        # out.
        _rx(
            r"(?i)\bnet(?:\.exe)?[ \t]+user[ \t]+\S+[ \t]+"
            r"(?!/)(\S+)"
        ),
        # Erlang/Elixir config tuple — ``{password, "v"}`` — the bare
        # atom is the credential name; plain ``key`` is too generic
        # for tuple pairs so it stays out.
        _rx(
            r"(?i)\{\s*(?:\w*(?:secret|token|password|passwd"
            r"|credential|auth)\w*|api[_-]?key)\s*,\s*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*')"
        ),
        # PuTTY family ``-pw``, sqlcmd ``-P`` (uppercase — the
        # password flag), twine ``-p``, keytool ``-(store|key)pass``;
        # cmdkey-style ``/pass:v``.
        _rx(
            r"\b(?:putty|plink|pscp|psftp|pageant)\b[^\n]*?"
            r"[ \t]-pw[ \t=]*(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"\b(?:sqlcmd|bcp|sqlservr)\b[^\n]*?"
            r"[ \t]-P[ \t=]*(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"\b(?:twine|flit)\b[^\n]*?[ \t]-p[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"(?i)-(?:src|dest)?(?:store|key)pass(?:word)?[ \t=]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"(?i)/(?:pass|password|pwd)[ \t]*:[ \t]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # RDP ``/p:v`` (xfreerdp family) and VNC single-dash
        # ``-passwd v``.
        _rx(
            r"(?i)\bxfreerdp\w*\b[^\n]*?/p:"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"(?i)\b(?:x11vnc|vncserver|vncpasswd|tightvnc|tigervnc)"
            r"\b[^\n]*?[ \t]-passwd(?:word)?[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # Password-subcommand positionals — ``mysqladmin … password
        # p`` and ``rabbitmqctl change_password u p``.
        _rx(
            r"(?i)\bmysqladmin\b[^\n]*?\bpassword[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"(?i)\brabbitmqctl[ \t]+change_password[ \t]+\S+[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # Tool-scoped short flags carrying secrets — ``ipmitool
        # -P``, ``useradd``/``usermod -p`` (the crypted password),
        # ``snmp* -A``/``-X`` (auth/privacy passphrases), and
        # ``doctl auth init -t``.
        _rx(r"\bipmitool\b[^\n]*?[ \t]-P[ \t=]*(\S+)"),
        _rx(r"\b(?:useradd|usermod)\b[^\n]*?[ \t]-p[ \t=]*(\S+)"),
        _rx(r"\bsnmp[a-z]*\b[^\n]*?[ \t]-[AX][ \t=]*(\S+)"),
        _rx(
            r"\bdoctl[ \t]+auth[ \t]+init\b[^\n]*?[ \t]-t[ \t=]*"
            r"(\S+)"
        ),
        # ``net use`` password positional — either side of the
        # ``/user:`` flag; a ``/``-led token is another flag.
        _rx(
            r"(?i)\bnet[ \t]+use[ \t]+(?:[\w*]:[ \t]+)?\\\\\S+[ \t]+"
            r"(?:/u(?:ser)?:[^\s]+[ \t]+)?(?!/)"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # Travis CI ``secure:`` var — an encrypted env blob; the
        # length floor keeps ``secure: true`` prose out.
        _rx(
            r"(?im)^[ \t]*secure[ \t]*:[ \t]*"
            r"([A-Za-z0-9+/=._~-]{16,})"
        ),
        # Credential-pair encodings — smbclient ``-U user%pass``,
        # lftp ``-u user,pass``, Oracle tools ``user/pass[@db]``.
        _rx(
            r"(?i)\b(?:smbclient|smbget|smbpasswd|rpcclient|winexe)"
            r"\b[^\n]*?[ \t]-U[ \t]*\S+%([^\"'\s]+)"
        ),
        _rx(
            r"(?i)\blftp\b[^\n]*?[ \t]-u[ \t]*[\"']?\S+,"
            r"([^\"',\s]+)"
        ),
        # Oracle-style ``tool user/password@service`` — the
        # password sits between the first ``/`` and the ``@`` (or
        # whitespace/end); a greedy ``\S+`` would land on the
        # service name instead.
        _rx(
            r"(?i)\b(?:sqlplus|sqlldr|sqlcl|exp|expdp|imp|impdp"
            r"|rman|tnsping|orapki)\b(?:[ \t]+\S+)*?"
            r"[ \t]+\S+?/([^\s/@\"']+)(?=[@\s\"']|$)"
        ),
        # ``openssl passwd`` takes the plaintext positionally after
        # the algorithm flag — a ``-``-led token is a flag, not the
        # plaintext (``-stdin`` reads interactively).
        _rx(r"\bopenssl[ \t]+passwd(?:[ \t]+-\w+)*[ \t]+((?!-)\S+)"),
        # Header value inside a quoted argument —
        # ``-H "X-Api-Key: hunter2"``, ``-H "Authorization: Bearer
        # t"``. The credential word can lead the header name
        # (``Authorization``), so the run before it can be empty;
        # group 1 is the header value.
        _rx(
            r"(?i)[\"'][\w-]*(?:key|token|secret|auth"
            r"|password|passwd)[\w-]*[ \t]*:[ \t]*"
            r"([^\"'\s][^\"'\r\n]*?)[\"']"
        ),
        # openssl password arguments use a scheme prefix —
        # ``-pass pass:pw``, ``-passin pass:pw``.
        _rx(r"(?i)-pass(?:in|out)?[ \t=]+pass:(\S+)"),
        # PowerShell ``ConvertTo-SecureString`` takes the plaintext
        # as a quoted literal — mask it, keep the flags.
        _rx(
            r"(?i)convertto-securestring[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])+\"|'(?:\\.|[^'\\\r\n])+')"
        ),
        # XML/app.config attribute pairs — the credential name sits
        # in ``key=``/``name=`` and the secret in ``value=``.
        _rx(
            r"(?i)\b(?:key|name)[ \t]*=[ \t]*[\"']" + ENV_NAME_PATTERN +
            r"[\"'][ \t]+value[ \t]*=[ \t]*(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*')"
        ),
        # Redis config — ``requirepass pw`` / ``masterauth pw``;
        # line-anchored like .netrc.
        _rx(
            r"(?im)^[ \t]*(?:requirepass|masterauth)[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _LDAP_ROOTPW_RX,
        # XML element text — ``<password>hunter2</password>``,
        # ``<db.password>x</db.password>``: the tag name carries the
        # credential word; ``<key>`` alone is a plist/config *name*
        # element so it stays out. Group 1 is the text node.
        _rx(
            r"(?i)<(?!key>)[\w.-]*(?:key|secret|token|password"
            r"|passwd|credential|auth|pw)[\w.-]*>[ \t]*"
            r"([^<\s][^<\r\n]*?)[ \t]*</"
        ),
        # SQL — ``IDENTIFIED [WITH x] BY [PASSWORD] 'pw'`` and
        # Postgres-style ``WITH PASSWORD 'pw'``; quoted only so
        # prose stays out.
        _rx(
            r"(?i)(?:identified[ \t]+(?:with[ \t]+\S+[ \t]+)?by"
            r"|with[ \t]+password)[ \t]+"
            r"(?:password[ \t]+)?(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*')"
        ),
        # Commented-out secrets — ``# password=x``,
        # ``// api_key=x``, ``<!-- token=x -->``, ``; secret=x``.
        # A credential parked in a comment still ships, and a
        # `` #`` comment trailing any matched line can carry a
        # second secret the first finding would hide. Unanchored:
        # the comment may sit behind code.
        _rx(
            r"(?<![\w])(?:#+|//+|<!--|;)[ \t]*"
            + ENV_NAME_PATTERN +
            r"[ \t]*[:=][ \t]*(?:"
            r"\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?'"
            r"|`(?:\\.|[^`\\\r\n])*?`"
            r"|\S(?:[^\n\\]|\\\r?\n)*"
            r")"
        ),
        # Bare mid-line ``name = value`` — a credential-shaped name
        # claims the next token wherever the pair sits:
        # ``docker -e KEY=v``, ``--from-literal=key=v``,
        # ``Cookie: key=v``, ``config:set KEY=v``. Comparisons
        # (``==``) stay out; the value stops at whitespace,
        # quotes and closers but keeps openers so the
        # code-assignment guard still sees ``name(`` calls.
        # Group 1 is the token.
        _rx(
            r"(?<!\w)" + ENV_NAME_PATTERN + r"[ \t]*=(?!=)[ \t]*"
            r"([rRbBuUfF]{0,3}(?:\"(?:\\.|[^\"\\\r\n])*?\""
            r"|'(?:\\.|[^'\\\r\n])*?')"
            r"|[^\s'\"&;,)\]}#]+)"
        ),
        _CRED_TUPLE_RX,
        # Explicit auth constructors — ``HTTPBasicAuth("u", "pw")``:
        # the class name declares the second positional is the
        # password.
        _rx(
            r"(?i)\b(?:HTTPBasicAuth|HTTPDigestAuth|HTTPProxyAuth"
            r"|BasicAuth)\(\s*"
            r"(?:\"(?:\\.|[^\"\\\r\n])*?\"|'(?:\\.|[^'\\\r\n])*?')"
            r"\s*,\s*"
            r"(\"(?:\\.|[^\"\\\r\n])*?\"|'(?:\\.|[^'\\\r\n])*?')"
        ),
        # Inline-map bare value — ``{api_key: v}`` (YAML flow
        # mappings): the mid-line ``:`` arm already owns quoted
        # values, so this bare token must start *off* a quote —
        # ``{"k": "it's …"}`` would otherwise truncate at the
        # first space and leak the tail.
        _rx(
            r"\{\s*\\?[\"']?" + ENV_NAME_PATTERN +
            r"[\"']?\s*:\s*[^\s'\"`,}\]]+"
        ),
        # nginx/Apache header directives —
        # ``proxy_set_header Authorization "Bearer t"``,
        # ``add_header X-Api-Key "k"``: group 1 is the quoted
        # header value, masked inside its quotes.
        _rx(
            r"(?i)\b(?:proxy_set_header|add_header|set_header"
            r"|more_set_headers|more_set_input_headers)[ \t]+"
            r"[\w-]*(?:key|token|secret|auth|password|passwd)"
            r"[\w-]*[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*?\"|'(?:\\.|[^'\\\r\n])*?')"
        ),
        # HAProxy ``stats auth user:pass``/``stats admin`` — a config
        # directive whose ``user:pass`` pair is a credential.
        _rx(
            r"(?im)^[ \t]*stats[ \t]+(?:auth|admin)[ \t]+\S+:"
            r"([^\s,;\"']+)"
        ),
        # CMS config writers — ``wp config set NAME v``,
        # ``wp option add|update NAME v``, ``drush config:set`` —
        # the option name carries the credential word and the value
        # is a bare positional.
        _rx(
            r"(?i)\b(?:wp[ \t]+config[ \t]+set|wp[ \t]+option[ \t]+"
            r"(?:add|update)|drush[ \t]+(?:config:set|config-set|"
            r"cset|state:set))[ \t]+" + ENV_NAME_PATTERN +
            r"[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s,;]+)"
        ),
        # KV stores — ``consul kv put``, ``vault kv put``,
        # ``etcdctl put`` — when the key path itself names a
        # credential (a ``secret/`` mount path counts: its value is
        # secret by convention).
        _rx(
            r"(?i)\b(?:kv[ \t]+put|etcdctl[ \t]+put)[ \t]+"
            r"\S*(?:key|secret|token|password|passwd|pw|credential"
            r"|auth)\S*[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s,;]+)"
        ),
        # Crypt-style password hashes — ``$apr1$``, ``$2y$`` bcrypt,
        # ``$5$``/``$6$`` sha-crypt, ``{SHA}``/``{SSHA}`` and the
        # LDAP/dovecot scheme set. The scheme marker is unambiguous
        # so the token flags wherever it appears. Group 1 only.
        _rx(
            r"(\$(?:apr1|1|2a|2b|2x|2y|5|6)\$[A-Za-z0-9./$=,]+"
            r"|\{(?i:sha|ssha|md5|smd5|crypt|blf-crypt|argon2"
            r"|pbkdf2|scram|ssha256|ssha512|sha256|sha512)\}"
            r"[^\s\"'<>\],};)]+)"
        ),
        # SMTP/IMAP ``AUTH PLAIN <b64>`` — tagged
        # ``a1 AUTHENTICATE PLAIN`` too — the blob decodes to
        # ``\0user\0pass``.
        _rx(
            r"(?im)^[ \t]*(?:\w+[ \t]+)?AUTH(?:ENTICATE)?[ \t]+"
            r"PLAIN[ \t]+([A-Za-z0-9+/=]{10,})[ \t]*$"
        ),
        # Password-argument tools — hydra, medusa, crackmapexec/
        # netexec, evil-winrm, smbmap, enum4linux, psexec: the
        # password rides ``-p`` (lowercase; ``-P`` is a list file
        # or port on most of these tools, and ncrack's ``-p`` is
        # a port spec — its ``--pass`` is the long-flag arm).
        _rx(
            r"\b(?i:hydra|medusa|crackmapexec|cme|nxc|netexec"
            r"|evil-winrm|smbmap|enum4linux(?:-ng)?|psexec"
            r"|racadm|idracadm?)\b"
            r"[^\n]*?[ \t]-p[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|(?:\\.|[^\s\\|&;])+)"
        ),
        # ``radtest user pass host port secret`` — arg2 is the user
        # password, arg5 the NAS shared secret; either may be
        # quoted (``"hun ter2"`` is one token, not two).
        _rx(
            r"\bradtest[ \t]+" + _CLITOK + r"[ \t]+"
            r"(" + _CLITOK + r")"
        ),
        _rx(
            r"\bradtest(?:[ \t]+" + _CLITOK + r"){4}[ \t]+"
            r"(" + _CLITOK + r")"
        ),
        # Kerberos ``kadmin -w pass`` / ``kadmin.local -q
        # "addprinc -pw pass u"`` — ``-w``/``-pw`` carry the
        # password, including inside the quoted subcommand.
        _rx(
            r"(?i)\bkadmin(?:\.local)?\b[^\n]*?[ \t]"
            r"-(?:pw|w)[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'"
            r"|(?:\\.|[^\s\\\"'|&;])+)"
        ),
        # A second ``-pw`` in the same command (quoted subcommand
        # under ``-q``, or a putty line) — lowercase-only so
        # ``grep -Pw`` stays out.
        _rx(
            r"[ \t]-pw[ \t=]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # ``pulumi config set [--secret] NAME v`` — the value is a
        # bare positional; boolean/value flags may sit between the
        # verb and the credential-shaped name.
        _rx(
            r"(?i)\bpulumi[ \t]+config[ \t]+set[ \t]+"
            r"(?:--\w+(?:[ \t=]+\S+)?[ \t]+)*"
            r"(?:[\w.-]+:)*" + ENV_NAME_PATTERN +
            r"[ \t]+(" + _CLITOK + r")"
        ),
        # Space-separated env-setters — ``cf set-env APP NAME v``,
        # ``netlify env:set NAME v``, ``render env:set NAME v``.
        _rx(
            r"(?i)\b(?:cf[ \t]+set-env[ \t]+\S+|netlify[ \t]+env:set"
            r"|render[ \t]+env:set)[ \t]+" + ENV_NAME_PATTERN +
            r"[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # ``gh secret set NAME --body v``/``-b v`` — secret bodies
        # ride the body flag; ``gh variable set`` only when the
        # variable name itself is credential-shaped.
        _rx(
            r"(?i)\bgh[ \t]+(?:secret[ \t]+set[ \t]+\S+|variable"
            r"[ \t]+set[ \t]+" + ENV_NAME_PATTERN + r")"
            r"(?:[^|&;\n]|\"(?:\\.|[^\"\\\r\n])*\""
            r"|'(?:\\.|[^'\\\r\n])*')*?[ \t](?:-b|--body)[ \t=]*"
            r"(" + _CLITOK + r")"
        ),
        # macOS ``security add-*-password -w`` — ``-w``'s operand is
        # the password being stored. (``find-*-password -w`` prints
        # instead; treating the next token as a secret would eat a
        # ``|`` pipeline.) hiera-eyaml ``encrypt -s`` same shape.
        _rx(
            r"(?i)\bsecurity[ \t]+add-\w+-password\b"
            r"[^\n]*?[ \t]-w[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|(?:\\.|[^\s\\|&;])+)"
        ),
        _rx(
            r"(?i)\beyaml[ \t]+encrypt\b[^\n]*?[ \t]-s[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # Windows ``schtasks /ru u /rp p`` — ``/rp`` carries the
        # run-as password; the value stops before the next
        # ``/flag``.
        _rx(
            r"(?i)\bschtasks\b[^\n]*?/rp[ \t:]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|[^/\s][^\s]*)"
        ),
        # ``rclone config create <remote> <backend> <credname>
        # <value>`` / ``update <remote> <credname> <value>`` — one
        # or two positionals before the credential-keyed pairs.
        # The value group absorbs every following ``NAME value``
        # pair, credential-named or not — a bare ``region us``
        # between two secrets must not reopen the mask.
        _rx(
            r"(?i)\brclone[ \t]+config[ \t]+(?:create|update)[ \t]+"
            r"(?:\S+[ \t]+){1,2}" + ENV_NAME_PATTERN +
            r"[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'"
            r"|(?:\\.|[^\s\\|&;])+"
            r"(?:[ \t]+\S+[ \t]+(?:\"(?:\\.|[^\"\\\r\n])*\""
            r"|'(?:\\.|[^'\\\r\n])*'|(?:\\.|[^\s\\|&;])+))*)"
        ),
        # ``.pgpass`` five-field rows ``host:port:db:user:pass`` —
        # a generic colon chain is prose-shaped anywhere else, so
        # this arm is gated to the filename
        # (``FILE_GATED_PATTERNS``). Group 1 is the password field.
        _PGPASS_RX,
        # ``composer config http-basic.<host> user pass`` and
        # jenkins-cli ``-auth user:pass`` — credential pairs as
        # positionals after a tool-scoped marker.
        _rx(
            r"(?i)\bcomposer[ \t]+config[ \t]+http-basic\S*[ \t]+"
            r"(?:\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"(?i)\bjenkins-cli\b[^\n]*?[ \t]-auth(?:entication)?"
            r"[ \t=]*(\"(?:\\.|[^\"\\\r\n])+\"|'(?:\\.|[^'\\\r\n])+'|\S+:\S+)"
        ),
        # Single-positional credential arguments —
        # ``cargo login <token>``, ``nuget setApiKey <key>``,
        # ``dotnet nuget push -k``-style bare tails.
        _rx(
            r"(?i)\b(?:cargo[ \t]+login|nuget[ \t]+setApiKey)[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|(?:\\.|[^\s\\|&;])+)"
        ),
        # Secret-store CLIs — ``az keyvault secret set --value``,
        # ``aws ssm put-parameter --value``, ``secretsmanager
        # create-secret --secret-string`` — the secret follows a
        # scoped ``--value``/``--secret-string`` flag.
        _rx(
            r"(?i)\b(?:keyvault[ \t]+secret[ \t]+set|ssm[ \t]+"
            r"put-parameter|secretsmanager[ \t]+(?:put-secret-value"
            r"|update-secret|create-secret))\b[^\n]*?[ \t]"
            r"--(?:value|secret-string)[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # ``doppler secrets set NAME v`` — the value is a bare
        # positional after the credential-named key.
        _rx(
            r"(?i)\bdoppler[ \t]+secrets[ \t]+set[ \t]+"
            + ENV_NAME_PATTERN +
            r"[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # Same shape: ``credstash put [-k kms] NAME v``,
        # ``chamber write <service> NAME v``, ``redis-cli SET
        # NAME v`` — a credential-named key followed by the bare
        # value positional.
        _rx(
            r"(?i)\bcredstash[ \t]+(?:put|putsecret)[ \t]+"
            r"(?:-\w+[ \t=]+\S+[ \t]+)*"
            + ENV_NAME_PATTERN +
            r"[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"(?i)\bchamber[ \t]+write[ \t]+\S+[ \t]+"
            + ENV_NAME_PATTERN +
            r"[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"(?i)\bredis-cli\b[^\n]*?[ \t]SET[ \t]+"
            + ENV_NAME_PATTERN +
            r"[ \t]+(" + _CLITOK + r")"
        ),
        # ``conjur variable set|values add -i id -v value`` — the
        # secret rides ``-v``.
        _rx(
            r"(?i)\bconjur[ \t]+variable\b[^\n]*?[ \t]-v[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # ``mc admin user add ALIAS ACCESSKEY SECRETKEY`` — the
        # secret key is the third positional after ``add`` and may
        # be quoted.
        _rx(
            r"(?i)\bmc[ \t]+admin[ \t]+user[ \t]+add[ \t]+"
            r"(?:" + _CLITOK + r"[ \t]+){2}(" + _CLITOK + r")"
        ),
        # InfluxDB 1.x single-dash long flag ``-password``.
        _rx(
            r"(?i)\binflux\b[^\n]*?[ \t]-password[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # ``sendemail -xp pass`` — ``-xp`` is the auth password
        # (``-xu`` is the user).
        _rx(
            r"(?i)\bsendemail\b[^\n]*?[ \t]-xp[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # ``signtool sign /f cert.pfx /p pass`` — ``/p`` is the
        # cert password; ``nuget -Password`` is the same shape in
        # single-dash form.
        _rx(
            r"(?i)\bsigntool\b[^\n]*?/p[ \t]+"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        _rx(
            r"(?i)\bnuget\b[^\n]*?[ \t]-Password[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # ``rar/unrar -pPASS`` — the archive password is glued to
        # the flag; ``veracrypt -p pass`` is the space form.
        _rx(r"\b(?:rar|unrar)\b[^\n]*?[ \t]-p(\S+)"),
        _rx(
            r"(?i)\bveracrypt\b[^\n]*?[ \t]-p[ \t=]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|\S+)"
        ),
        # ``echo "user:pass" | chpasswd``/``newusers`` — the
        # credential pair is the last token before the pipe.
        _rx(
            r"[\"']?([\w.-]+:[^\s\"'|]+)[\"']?[ \t]*"
            r"\|[ \t]*(?:sudo[ \t]+)?(?:chpasswd|newusers)\b"
        ),
        # Tcl/expect — the sent string after a ``password`` prompt
        # is the credential (``expect "Password:" ; send "x\r"``).
        _rx(
            r"(?i)\bexpect\b[^\n]*?password[^\n]*?[;\n][ \t]*"
            r"send[ \t]+(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*')"
        ),
        # Capistrano ``set :password, "v"`` — symbol plus comma;
        # only cred-word symbols count.
        _rx(
            r"(?i)\bset[ \t]+:\w*(?:key|secret|token|password"
            r"|passwd|credential|auth)\w*[ \t]*,[ \t]*"
            r"(\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*')"
        ),
        # Ansible vault blob — ``$ANSIBLE_VAULT;1.1;AES256`` plus
        # the hex-only ciphertext lines under it (the body is the
        # offline-crackable secret).
        _rx(
            r"(\$ANSIBLE_VAULT;[0-9.]+;[A-Z0-9_]+"
            r"(?:(?:[ \t]*\r?\n)+[ \t]*[0-9a-fA-F]+)*)"
        ),
        # ``password x`` directive in mail-client rc files —
        # gated to msmtprc/esmtprc/fetchmailrc
        # (``FILE_GATED_PATTERNS``).
        _MAILPASS_RX,
        # Java ``.properties`` whitespace separator — ``api_key hunter2``
        # is a legal properties line but plain prose elsewhere, so this
        # arm only fires under a matching file extension (see
        # ``FILE_GATED_PATTERNS``). Group 1 is the rest-of-line value.
        _rx(
            r"(?im)^[ \t]*" + ENV_NAME_PATTERN + r"[ \t]+"
            r"([^\s][^\r\n]*?)[ \t]*(?:\r?$|$)"
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

# Patterns that only fire for matching file names — keyed on the
# compiled pattern object so inserting arms cannot drift an index.
# The whitespace-separated ``key value`` form is legal Java
# ``.properties`` syntax but ordinary prose anywhere else.
FILE_GATED_PATTERNS: dict[re.Pattern[str], tuple[str, ...]] = {
    PATTERNS["env_assignment"][-1]: (".properties", ".props"),
    _MAILPASS_RX: ("msmtprc", "esmtprc", "fetchmailrc"),
    _PGPASS_RX: (".pgpass", "pgpass.conf"),
}

# Arms whose whole match legitimately looks like a code expression to
# ``_looks_like_code_assignment`` — the capture group declares the
# sensitive token, so the container-shape heuristic does not apply.
# (The bare mid-line arm keeps the guard: its group carries the ``(``
# evidence the heuristic reads.)
GUARD_EXEMPT_PATTERNS: frozenset[re.Pattern[str]] = frozenset(
    {_CRED_TUPLE_RX, _LDAP_ROOTPW_RX}
)

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
