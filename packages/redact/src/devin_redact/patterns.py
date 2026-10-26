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
            # ``readonly``/``typeset``/``env``/``set`` and flag-taking
            # ``declare -x`` — bind the same secret. Case-insensitive
            # so Dockerfile ``ENV``/``ARG KEY=v`` and cmd ``SET``
            # match the same anchor. A list bullet (``-``/``*``/``+``)
            # or comment opener (``#``/``//``/``<!--``/``;``) before
            # the name hides the same bind — docker-compose
            # ``environment:`` lists and commented-out credentials.
            r"(?:(?i:export|local|readonly|typeset|env|declare|arg|set)"
            r"\s+(?:-\w+\s+)*|(?:[*+-]|#+|//+|<!--|;)\s*)?"
            # The name can hide behind a receiver — ``cfg.api_key``,
            # ``self.api_key``, ``config["api_key"]``: a hardcoded
            # secret is the same wherever it is bound.
            r"(?:"
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\[\s*[\"']?"
            + ENV_NAME_PATTERN + r"[\"']?\s*\]"
            r"|(?:[A-Za-z_]\w*\.)*\s*[\"']?" + ENV_NAME_PATTERN + r"[\"']?"
            r")"
            # A ``\``-continued separator — ``key = \<newline>"v"`` —
            # puts the literal on the next physical line.
            r"\s*[:=][ \t]*(?:\\\r?\n[ \t]*)*\s*(?:"
            # An annotation head first — ``name: T = value``: the
            # ``T`` and its ``=`` belong to the match so a literal
            # default on a later line stays inside the span.
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
        _rx(
            r"(?mi)^[\s\ufeff]*(?:env|arg)[ \t]+"
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
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        # CLI credential flags — ``sshpass -p``, ``curl -u u:p``,
        # ``redis-cli -a``, ``ldapsearch -w``, ``mosquitto_* -P``.
        # Group 1 is the token, quoted or bare.
        _rx(
            r"(?i)\b(?:sshpass[ \t]+-p|(?:curl|wget|httpie?|fetch)\S*"
            r"[ \t]+(?:-u|--user)|redis-cli[ \t]+-a"
            r"|ldapsearch[ \t]+-w|mosquitto_\w+[ \t]+-P)[ \t=]*"
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        # mysql family ``-p<pass>`` — the value rides attached and
        # may follow other flags (``-u root -psecret``). Kept
        # case-sensitive: ``-P`` is the *port* flag.
        _rx(
            r"\b(?:mysql|mysqldump|mariadb|mysqladmin|mysqlcheck)"
            r"\w*\b[^\n]*?\s-p(\S+)"
        ),
        # htpasswd batch mode — ``-b file user pass``.
        _rx(r"(?i)\bhtpasswd[ \t]+-b\w*[ \t]+\S+[ \t]+\S+[ \t]+(\S+)"),
        # Long option carrying the secret as the next argument —
        # ``--password pw``, ``--http-password pw``, ``--api-key k``,
        # ``--client-secret s``, ``--auth-token t``. The flag must
        # *end* in the credential word, so ``--password-file f`` and
        # ``--token-type t`` stay out.
        _rx(
            r"(?i)--[\w-]*(?:password|passwd|passphrase|pass|secret"
            r"|token|api[-_]?key|access[-_]?key|client[-_]?secret"
            r"|auth[-_]?token|bearer)[ \t=]+"
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        # Tool flags where the secret rides a short option or a
        # named setter — docker/podman ``login -p``, zip/unzip ``-P``
        # (uppercase, case matters), 7z ``-p``, and
        # ``aws configure set <name> <value>``.
        _rx(
            r"\b(?:docker|podman)[ \t]+login\b[^\n]*?[ \t]-p[ \t=]*"
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        _rx(r"\b(?:zip|unzip)\b[^\n]*?[ \t]-P[ \t=]*(\S+)"),
        _rx(r"\b7z[ \t]+\S+[ \t]+-p(\S+)"),
        _rx(
            r"(?i)\baws[ \t]+configure[ \t]+set[ \t]+"
            r"\S*(?:key|secret|token)\S*[ \t]+(\S+)"
        ),
        _rx(
            r"(?i)\b(?:poetry|pip|npm|gem|bundle)[ \t]+config(?:"
            r"[ \t]+set)?[ \t]+\S*(?:key|secret|token|pass\w*)"
            r"\S*[ \t]+(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        # PuTTY family ``-pw``, sqlcmd ``-P`` (uppercase — the
        # password flag), twine ``-p``, keytool ``-(store|key)pass``;
        # cmdkey-style ``/pass:v``.
        _rx(
            r"\b(?:putty|plink|pscp|psftp|pageant)\b[^\n]*?"
            r"[ \t]-pw[ \t=]*(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        _rx(
            r"\b(?:sqlcmd|bcp|sqlservr)\b[^\n]*?"
            r"[ \t]-P[ \t=]*(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        _rx(
            r"\b(?:twine|flit)\b[^\n]*?[ \t]-p[ \t=]*"
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        _rx(
            r"(?i)-(?:src|dest)?(?:store|key)pass(?:word)?[ \t=]+"
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        _rx(
            r"(?i)/(?:pass|password|pwd)[ \t]*:[ \t]*"
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
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
        _rx(
            r"(?i)\b(?:sqlplus|sqlldr|exp|expdp|imp|impdp|rman)"
            r"\s+\S+/(\S+)"
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
            r"(\"[^\"\r\n]+\"|'[^'\r\n]+')"
        ),
        # XML/app.config attribute pairs — the credential name sits
        # in ``key=``/``name=`` and the secret in ``value=``.
        _rx(
            r"(?i)\b(?:key|name)[ \t]*=[ \t]*[\"']" + ENV_NAME_PATTERN +
            r"[\"'][ \t]+value[ \t]*=[ \t]*(\"[^\"\r\n]*\"|'[^'\r\n]*')"
        ),
        # Redis config — ``requirepass pw`` / ``masterauth pw``;
        # line-anchored like .netrc.
        _rx(
            r"(?im)^[ \t]*(?:requirepass|masterauth)[ \t]+"
            r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|\S+)"
        ),
        # SQL — ``IDENTIFIED [WITH x] BY [PASSWORD] 'pw'``; quoted
        # only so prose stays out.
        _rx(
            r"(?i)identified[ \t]+(?:with[ \t]+\S+[ \t]+)?by[ \t]+"
            r"(?:password[ \t]+)?(\"[^\"\r\n]*\"|'[^'\r\n]*')"
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
