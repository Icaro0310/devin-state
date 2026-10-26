# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Detection coverage expansion (adversarial audit of the privacy
  boundary): GitLab (`glpat-`/`gldt-`/`glrt-`/`glcbt-`/`glagent-`),
  npm (`npm_`), PyPI (`pypi-`), DigitalOcean (`dop_v1_`), SendGrid
  (`SG.`), Square (`sq0atp-`/`sq0csp-`), Shopify
  (`shpat_`/`shpca_`/`shppa_`/`shpss_`), Google OAuth (`ya29.`),
  Hugging Face (`hf_`), Stripe webhook secrets (`whsec_`), Slack app
  tokens (`xapp-`) and age secret keys (`AGE-SECRET-KEY-`); JWTs with
  short payload/signature and `alg:none` empty signatures; PGP
  `PRIVATE KEY BLOCK` and unterminated PEM blocks;
  `Authorization: Basic <b64>`; case-insensitive `Bearer` with
  `[\s:=]` separators.
- New secret categories `connection_uri` (`scheme://user:pass@host`,
  any scheme) and `webhook_url` (Slack, Discord, Office365) — both
  hold `publication_status` at `BLOCKED`.
- `env_assignment` learns `:` (YAML) separators, JSON/dict/JS pairs
  anywhere on a line, escaped JSON quotes and camelCase/lowercase
  names; machine prefixes match unanchored so `api_key%3D<token>`
  still lands.
- Encoding coverage: UTF-8 with stray NUL, UTF-16 (BOM or NUL-parity
  BOM-less), lossy `surrogateescape` decode for text with a few
  invalid bytes, and a printable projection (`kind=binary-projection`)
  that rejoins secrets split by control bytes or ANSI escapes —
  detection-only.
- JSON dict *keys* scanned for secret-shaped content and now rewritten
  on redact (`{"sk-…": "enabled"}` → `{"<REDACTED:…>": "enabled"}`).
- `verify-publish` hardening: `index.json`/`index.md` enumerate but
  never limit coverage — on-disk session files are unioned into the
  scan set so a crafted/stale index omitting a dirty session cannot
  report `CLEAN`; entries resolving outside the export dir warn.
- `redact --apply` on a text-marked file with a few undecodable bytes
  rewrites through `surrogateescape`, byte-exact for the
  undecodable regions.
- `devin-redact diff <paths> [-o report.html]` — self-contained HTML
  before/after report for human review of sensitive exports. Renders the
  `scan` report as summary cards, category chips and a per-finding table
  (file, `table.column#rowid`/`line` location, category, masked *before*
  preview, `<REDACTED:sha256prefix>` *after* tag, fingerprint) and joins
  the dry-run `redact()` plan so each row is marked `planned` or
  `detection-only` (cross-chunk secrets the per-cell rewrite cannot
  cover). Same secrecy contract as the JSON/SARIF outputs: secret text
  never appears, and every dynamic value is HTML-escaped. Unreadable
  targets fail loudly (exit 2, no report); a clean input still produces
  a valid "no findings" page. Output is always written utf-8.
- Tests: adversarial-instruction corpus proving scanner input is
  content, not configuration — `scan_text` still reports a planted
  secret and `redact_text` still masks it when the surrounding free
  text says "don't mask", "do not redact", "never apply", "skip this"
  or "avoid applying", or injects an "IGNORE PREVIOUS" line
  (devin-state#91).

### Added

- `connection_uri` category — database/service URIs with embedded
  credentials (`postgres://user:pw@host`, `mongodb+srv://`, AMQP,
  Redis `redis://:pw@`) are detected and masked (devin-state#92).
- `webhook_url` category — Slack `hooks.slack.com`, Discord
  `discord.com/api/webhooks`, Google Chat and Teams/Office webhook
  endpoints are secrets in the URL itself and are masked
  (devin-state#92).
- Vendor-prefix coverage widened: GitLab `glpat-`, npm `npm_`,
  SendGrid `SG.`, OpenAI `sk-`, Stripe `sk_live`/`rk_`, Hugging Face
  `hf_`, DigitalOcean `dop_v1_`, Google `AIza`, and lowercase
  `password=`/`api_secret=` env names and YAML `name: value` pairs
  (devin-state#92).
- Unterminated PEM blocks (`-----BEGIN ... PRIVATE KEY-----` with no
  matching `END`) are detected and removed — a truncated capture no
  longer ships the key body (devin-state#92).

### Fixed

- Fail-closed decode gate (devin-state#92): a *text-named* blob
  (`.env`, `.txt`, `.json`, `.pem`, `id_rsa`, …) whose bytes fail
  every codec is now scanned lossy (surrogateescape + printable
  projection) instead of skipped — one invalid byte can no longer hide
  a credential from the staged-file gate. Binary-named blobs still
  skip.
- UTF-16 handling (devin-state#92): BOM'd input keeps its original
  endianness on write (`FE FF` stays big-endian), and a surrogate pair
  crossing the 8192-byte sniff boundary no longer flips the file to
  "binary, skip".
- JSON redaction preserves validity (devin-state#92): quoted
  `"key":"secret"` pairs keep their quotes (or gain them) so exports
  stay parseable; escape-aware value bodies mean `\"` inside a value
  no longer leaks the suffix, `=` inside a quoted value no longer
  suppresses detection, and an anchored pair cannot eat later
  same-line properties.
- JSON-object *keys* carrying credentials are rewritten on apply, not
  just values — `_key_strings` detections no longer survive
  `redact --apply` (devin-state#92).
- Type annotations (`api_key: str`, `token: Optional[str]`) are no
  longer flagged or redacted as secret assignments — quoted/YAML
  scalars with the same shape still are (devin-state#92).
- Dotted annotations whose terminal segment is lowercase by
  convention (`numpy.ndarray`, `collections.deque`, `socket.socket`)
  are suppressed like any other type, but only under the module
  namespace that owns them — `weakref.proxy` is an annotation while
  `password: customer.proxy` still flags and blocks the gate
  (devin-state#92).
- Import aliases are resolved from the scanned text itself —
  `import numpy as n` makes `n.ndarray` an annotation and
  `from collections import deque` binds the bare name, while an
  unbound alias (`api_key: n.ndarray` with no import) still flags.
  Relative (`from .x import y`) and wildcard (`from x import *`)
  imports bind the same way — `weakref`'s starred `ref` suppresses,
  `os`'s `environ` does not (devin-state#92).
- Parenthesized from-imports (`from collections import (deque)`),
  including the multi-line form and inline comments inside the parens,
  bind names like the plain form (devin-state#92).
- Alias resolution only applies where `x: T` can be an annotation —
  Python-typed files. An `import` line inside a `.env`/`.yaml` blob is
  inert text, so `api_key: n.ndarray` there still blocks the gate
  (devin-state#92).
- An annotated default no longer hides a hardcoded value —
  `api_key: str = "hunter2"` flags while `x: str = None` and
  `x: T = call()` stay annotations, and the rewrite scopes to the
  literal (`api_key: str = "<REDACTED:…>"`, still parseable)
  (devin-state#92).
- Import bindings only suppress outside string literals — a
  `name: value` line inside `'''`/`"""` is string content and always
  flags, and an `import` line inside one binds nothing, so a
  docstring cannot launder a credential through a wildcard or
  relative import (devin-state#92).
- A rebound import alias binds nothing — `import numpy as n`
  followed by `n = "x"`, `for n in`, `def n`, `class n`,
  `with ... as n`, `except ... as n`, `del n`, `n: T = v`, `n := v`
  or `case n` leaves `n.ndarray` a plain attribute read under a
  credential keyword, so it flags (devin-state#92).
- Finding previews no longer echo the match tail — `first…last`
  leaked the secret suffix (`api_…ret"`), and a short value leaked
  outright in SARIF and diff reports; previews are head-only now
  (devin-state#92).
- Triple-quoted values mask the whole literal — the single-quote
  arm used to stop at the empty `""`/`''` opener and leave
  `key = """\nsecret\n"""` with its body intact (devin-state#92).
- A parenthesized literal wrapped across lines now flags —
  `key = (\n "x"\n)` and `key: T = (\n "x"\n)` leak the same
  hardcoded value the one-line form did, and the rewrite stays
  parseable; tuples still fall through so a second literal in
  `("x", "y")` is never left half-masked. Union annotation heads
  (`str | None`) reach the multiline literal too (devin-state#92).
- Credential names behind a receiver now flag — `cfg.api_key`,
  `self.api_key`, and `config["api_key"]` bind hardcoded secrets
  the same as a bare `api_key`, and the quoted rewrite keeps
  the assignment parseable (devin-state#92).
- Call-bound secrets now flag — `f(api_key="x")` and
  `setdefault("api_key", "x")` bind literals the same way; the
  rewrite keeps the call parseable and comparisons
  (`api_key=="x"`) stay out (devin-state#92).
- Shell declaration prefixes beyond `export` now flag —
  `declare -x`, `local`, `readonly`, `typeset`, and `env`
  prefix assignments bind the same secret (devin-state#92).
- Implicit string concatenation now flags as one value —
  `key = "a" \<newline>"b"`, `key = ("a" "b")`, and
  `key = \<newline>"v"` keep the whole literal inside the
  mask and the rewrite stays parseable (devin-state#92).
- Dense-match scans are no longer quadratic — the same-category
  span containment check now bisects a sorted interval list,
  so `f(api_key="x", api_key="x", …)` walls scan in linear
  time (devin-state#92).
- Annotated defaults keep the literal's own shape — `b"…"`
  stays bytes and `("…",)` stays a one-tuple — and the
  trailing comment on an annotated assignment is dropped:
  it can carry a credential the single consumed finding
  hides from later scans (devin-state#92).
- `pw` joins the credential-name vocabulary (`db_pw=x`,
  `pw=x`, `ftp_pw x`), and LDAP `rootpw`/`olcRootPW`
  config lines flag under whitespace, `:` or `=`
  separators including `{SSHA}`-prefixed hashes — that
  scheme prefix looks like a container to the code guard,
  so the arm joins `GUARD_EXEMPT_PATTERNS` (devin-state#92).
- XML element text under a credential-named tag flags —
  `<password>x</password>`, `<db.password>x</db.password>` —
  while `<key>` name elements stay out so plist pairs and
  generic markup do not false-positive (devin-state#92).
- Crypt-scheme password hashes flag wherever they appear —
  `$apr1$`, `$2y$` bcrypt, `$5$`/`$6$` sha-crypt and
  `{SHA}`/`{SSHA}`/LDAP-dovecot scheme prefixes — covering
  `.htpasswd` lines, traefik `users` lists and bare
  `/etc/shadow`-style rows (devin-state#92).
- Positional secret carriers: `htpasswd`/`mosquitto_passwd`
  batch mode (`-b`, `-cb`, `-nb`), `wp config set`/`wp
  option update`/`drush config:set`, `consul kv put`/`vault
  kv put`/`etcdctl put` under a credential-named key path,
  HAProxy `stats auth user:pass`, `SSHPASS=x` (no underscore
  before `PASS`), and SMTP/IMAP `AUTH PLAIN <b64>`
  (devin-state#92).
- `.pgpass` five-field rows flag under a filename gate
  (`host:port:db:user:pass` is prose-shaped elsewhere);
  `composer config http-basic` pairs, jenkins-cli
  `-auth u:p`, `cargo login`/`nuget setApiKey` positional
  tokens, `az keyvault`/`aws ssm`/`secretsmanager`
  `--value`/`--secret-string` arguments, `doppler secrets
  set`, and the `$ANSIBLE_VAULT` marker plus its hex
  ciphertext body all flag (devin-state#92).
- Tool-scoped password flags: `-p` on hydra/medusa/
  crackmapexec/netexec/evil-winrm/smbmap/enum4linux/psexec
  (lowercase only — `-P` is a list file or port), `gh
  secret set --body`/`-b`, `gh variable set` under a
  credential-shaped name, macOS `security -w`, hiera-eyaml
  `encrypt -s`, `schtasks /rp`, and `rclone config
  create|update` credential-key positionals
  (devin-state#92).
- `setx` whitespace-separated matches keep the command,
  optional `/M` flag and variable name instead of
  collapsing to a bare tag; `.pgpass` rows treat `\:` as
  field content so escaped colons cannot shift the
  password field; quoted credential arguments with spaces
  (`composer http-basic`, `jenkins-cli -auth`, `cargo
  login`, `doppler secrets set`) mask whole instead of
  splitting at the first word; and blank lines inside a
  `$ANSIBLE_VAULT` ciphertext body no longer expose the
  remaining lines (devin-state#92).
- `security find-*-password -w` no longer eats a shell
  pipeline — only `security add-*-password` takes a `-w`
  operand; `gh secret set`/`gh variable set` tolerate
  options before `--body`; `rclone config update` (no
  backend positional) and multi-credential `config create`
  tails mask every keyed value (devin-state#92).
- Python literal prefixes survive on plain assignments too —
  `api_key = b"v"` (and `rb`/`f`/`u`) re-emits `b"<tag>"`
  instead of an unquoted tag that cannot parse — and YAML
  block scalars (`key: |`, `key: >`) mask the indented
  body lines that used to ship the secret (devin-state#92).
- Dockerfile `ENV`/`ARG` (case-insensitive, both `=` and the
  legacy whitespace separator), cmd `SET`/`EXPORT`, and URL
  query secrets (`?api_key=v`, `&token=v`, `;secret=v`,
  `#`-separated params) are now credential binds too
  (devin-state#92).
- List bullets (`- API_KEY=x`, docker-compose `environment:`)
  and commented-out credentials (`#`/`//`/`<!--`/`;` + `name=`)
  are masked instead of shipping — and a `#` comment trailing a
  matched line no longer hides a second credential from the
  scan: it is its own finding now (devin-state#92).
- `np` is no longer a hardcoded `numpy` owner — `api_key: np.ndarray`
  only suppresses when `import numpy as np` actually appears in the
  text; every other alias keeps resolving from real imports
  (devin-state#92).
- A `:`-separated env pair keeps its whitespace on redaction —
  `key: v` stays `key: <REDACTED:…>` so the line still reads as a
  YAML mapping instead of collapsing to a scalar, while `KEY=v`
  keeps the tight `KEY=<tag>` form (devin-state#92).
- The parenthesized-import matcher is per-character now — an
  unclosed `from x import (` scans linearly instead of
  exponentially partitioning the file (ReDoS; devin-state#92).
- A complete PEM block is reported once, not once per matching
  pattern — `scan_text` dedupes overlapping findings so one key no
  longer inflates the count (devin-state#92).
- `redact --apply` no longer silently truncates a UTF-16 file whose
  final code point is incomplete (devin-state#92). The truncated-tail
  tolerance that lets the bounded binary sniff and read-only scans
  judge the decodable head used to reach the rewrite too: only the
  decoded prefix was written while success was reported. The rewrite
  now re-verifies the whole file under the detected codec and carries
  the undecodable tail bytes through `_apply_text`, re-appending them
  verbatim — and a mid-content decode failure skips with a loud error
  instead of dropping bytes.
- Type-shaped credentials no longer bypass scanning (devin-state#92):
  `api_key: abc.def` matched the *dotted type* escape hatch in the
  annotation guard and reported CLEAN. A dotted path now only counts
  as an annotation when it is well-formed *and* its terminal segment
  is a builtin/typing name or a CapWords class (`pathlib.Path`,
  `datetime.datetime`, `models.User`, `typing.Any`) — the same check
  applies inside generics/unions, so `list[abc.def]` cannot smuggle a
  credential either. Real type annotations stay suppressed.
- String-span detection now uses Python's own tokenizer
  (devin-state#92): a `'''`/`"""` inside a comment or an ordinary
  quoted literal no longer opens a phantom docstring over later real
  annotations, and a `\`-escaped quote no longer closes one early —
  a credential sitting after `\""` inside a docstring flags again.
  Source the tokenizer rejects falls back to the delimiter scan,
  which now also skips escape-spelled delimiters.
- A flag landing in an unquoted Python value slot
  (`api_key: hunter2`, `x = hunter2`) now emits the tag quoted —
  `api_key: "<REDACTED:…>"` still parses where the bare tag did not;
  `.env` output keeps the plain `KEY=<REDACTED:…>` convention
  (devin-state#92).
- The parenthesized-import comment run is per-character too —
  `[^\n]*` after `#` let a `#####` run partition across iterations,
  the last exponential-backtracking shape in that matcher (CodeQL
  py/redos; devin-state#92).
- Structured-config credentials flag in place — Terraform
  `variable "k" { default = "v" }` masks the quoted default, an
  Ansible `!vault |` block scalar masks the ciphertext lines, an
  `.npmrc` `//host/:_authToken=v` keeps the option name, and
  `.netrc`/`.authinfo` positional entries (`machine h login u
  password p`, wrapped across lines, `default` entries, `account`
  values) mask only the password (devin-state#92).
- Command-line and config-format credentials flag in place —
  `kubectl --from-literal=k=v`, Docker `-e`/`--env`, `curl -u`/
  `--user`, `sshpass -p`, `redis-cli -a`, `mysql -p`, `htpasswd -b`,
  SQL `IDENTIFIED ... BY`, redis `requirepass`/`masterauth`, XML
  `key="name" value="v"` attribute pairs and direct secret-named
  attributes, Java properties escaped separators (`\=`, `\u003d`),
  and bare mid-line `name = value` (CLI args, cookies)
  all mask only the secret token; comparisons (`==`, `>=`) and
  code-constant RHS (`name(`, `[`, `{`) stay out (devin-state#92).
- The whitespace-separated `key value` form fires only for
  `.properties`/`.props` files — legal Java properties syntax there,
  prose anywhere else — via per-pattern file gating keyed on the
  compiled pattern object (devin-state#92).
- An env-shaped match inside a string literal that already carries
  a `<REDACTED:…>` tag is prior redaction output, not a fresh
  secret — re-matching a decoy there no longer rewrites the line
  (devin-state#92).
- Space-separated credential flags mask their argument —
  `--password`/`--api-key`/`--client-secret` and friends (flags
  ending in `-file`/`-type` carry names and stay out), tool flags
  `docker|podman login -p`, `zip|unzip -P`, `7z -p`,
  `aws configure set <name> <value>`, quoted header values like
  `-H "X-Api-Key: v"`, openssl `-pass pass:v`, and PowerShell
  `ConvertTo-SecureString "v"` (devin-state#92).
- More credential carriers mask in place — cmdkey `/pass:v`,
  smbclient `-U user%pass`, lftp `-u user,pass`, Oracle
  `user/pass[@db]`, `openssl passwd` positionals, PuTTY `-pw`,
  sqlcmd `-P`, keytool `-(store|key)pass`, `twine -p`,
  `poetry|pip|npm|gem|bundle config [set] <name> <value>`,
  `--passphrase` and `--oauth2-bearer` (devin-state#92).
- Credential values in call arguments and setter/DSL forms mask in
  place — `config.set("sec", "api_key", "v")`, `os.putenv`,
  `getenv`/`define`, dict-literal args like `cfg.update({...})`,
  fluent setters (`e.set_key("v")`), C `#define` quoted values,
  Emacs Lisp `setq`/`defvar`/`defcustom`, and plist
  `<key>/<string>` pairs (devin-state#92).
- fish `set -x`/`set -gx`, csh `setenv` and macOS
  `launchctl setenv` keep the command and variable name, masking
  only the value; `set -e -u -o pipefail` and bare option runs
  stay untouched (devin-state#92).
- `PASS`/`PWD`/`PASSPHRASE`/`PASSCODE`/`USERPASS` join the
  credential-name vocabulary as whole names or after an
  underscore — `DB_PASS=` and `FTP_PWD=` flag like `DB_PASSWORD=`
  while `compass`, `bypass`, `passport` and `OLDPWD` stay out
  (devin-state#92).
- Typed-language declarations flag — `const`/`let`/`var`/`val`,
  access/storage modifiers (`private static final String …`),
  builtin type words and Rust reference annotations
  (`const K: &str = "v"`, `&'a mut str`) — the rewritten line keeps
  its type head so it still parses (devin-state#92).
- Make/BSD-make operators (`:=`, `?=`, `+=`, `::=`) and Go
  short-var `apiKey := "v"` are separators now — the operator
  survives the mask (`KEY := <tag>`) instead of being eaten by it
  (devin-state#92).
- Windows `setx` (with `/M`), `net user <name> <password>`
  positionals, `git config [--global] name value`, Erlang/Elixir
  config tuples `{password, "v"}`, and two-argument call forms
  `f("NAME","v")`/`SetEnvironmentVariable("K","v")` mask the
  credential value (devin-state#92).
- Env subscripts with sigils or braces — `$ENV{KEY}`,
  `$_ENV['KEY']` — and dotted property-path names in call args
  (`setProperty("db.password", …)`, `ini_set("session.secret", …)`)
  flag; `compass`-family words still stay out (devin-state#92).
- SQL `WITH PASSWORD 'x'`, bare `Authorization: Basic <b64>`
  headers (a case-insensitive `(?i)` had made the lowercase-word
  guard also reject base64 of only letters), auth tuples
  `auth=("u","p")`/`credentials=("u","p")`/`HTTPBasicAuth("u","p")`
  (second element only, generic cred-name tuples stay code), bare
  inline-map values `{KEY: v}`, and nginx/Apache header directives
  (`proxy_set_header`, `add_header`, `set_header`) now mask the
  credential (devin-state#92).
- More tool-scoped carriers: xfreerdp `/p:v`, VNC `-passwd v`,
  `mysqladmin password`, `rabbitmqctl change_password`, `ipmitool
  -P`, `useradd`/`usermod -p`, `snmp* -A`/`-X`, `doctl auth init
  -t`, `net use` password positionals (both `/user:` orders), and
  Travis `secure:` blobs with a length floor so `secure: true`
  stays prose (devin-state#92).
- Oracle-style `user/password@service` credspecs (`sqlplus`,
  `sqlldr`, `sqlcl`, `exp`/`imp`/`expdp`/`impdp`, `rman`,
  `tnsping`, `orapki`) mask the password between the first `/` and
  the `@` — a greedy tail previously landed on the service name —
  and intervening positionals (`rman target u/p@h`) still match
  (devin-state#92).
- Positional/flagged credential carriers: `cf set-env APP NAME v`,
  `netlify env:set NAME v`, `render env:set NAME v`, `pulumi
  config set [--secret] NAME v`, `racadm`/`idracadm -p`,
  `radtest`'s user-password (arg2) and NAS shared secret (arg5),
  and kerberos `kadmin -w`/`-pw` including inside a quoted `-q`
  subcommand (devin-state#92).
- Mail-client rc files — `password x` / `password "x"` is a
  directive in `msmtprc`/`esmtprc`/`fetchmailrc` (including
  fetchmail's mid-line `poll … password "x"`) but prose elsewhere,
  so the arm is gated to those filenames (devin-state#92).
- Registry `login -p` now covers `skopeo`, `buildah`, `oras`,
  `crane (auth) login`, `helm registry login` and `podman-remote`,
  not just docker/podman; `docker run -p` port mappings stay
  untouched (devin-state#92).
- `credstash put [-k] NAME v`, `chamber write svc NAME v`,
  `redis-cli SET NAME v`, `conjur variable … -v`, `mc admin user
  add` secret-key positional, influx 1.x single-dash `-password`,
  `sendemail -xp`, and Capistrano `set :password, "v"` all mask
  the credential (devin-state#92).
- httpie `http METHOD url -a u:p`/`--auth` (method-scoped so the
  bare word "http" stays prose), curl `-U`/`--proxy-user`, all
  `ldap*` tools' `-w` (flag gaps now tolerated), `signtool /p`,
  `nuget -Password`, glued `rar`/`unrar -pPASS`, `veracrypt -p`,
  `user:pass | chpasswd`/`newusers` pipes, and expect scripts'
  `send` after a password prompt (devin-state#92).
- `.pgpass` rows of bare backslash escapes no longer trigger
  exponential backtracking — the field class excludes `\\` so a
  separator-free row fails fast (devin-state#92).
- Operand grammar is escape-aware and quote-aware throughout:
  `\|`/`\;`/`\"` inside a value no longer ends the mask early,
  quoted options containing `;`/`|` before `gh secret set --body`
  are skipped correctly, and the rclone tail absorbs
  non-credential `NAME value` pairs so a later credential pair
  cannot reopen the mask (devin-state#92).
- Quoted positionals are honored by `radtest` (both password
  operands), `mc admin user add`, and mail `password "..."`
  directives; a second `-pw` inside `kadmin -q "..."` subcommands
  is masked; `pulumi config set --secret ns:name v` matches
  namespaced keys; `redis-cli set` (lowercase) is covered
  (devin-state#92).
- Bare secret operands in tool-scoped arms now stop at shell
  separators — `cmd -p hunter2; rm` keeps its `;` boundary instead
  of absorbing it into the masked span (devin-state#92).
- The `from x import (` paren-block regex no longer backtracks
  exponentially on unclosed blocks containing `#…` comment runs —
  the comment branch is atomic via a lookahead+backreference
  emulation, closing the CodeQL "inefficient regular expression"
  alert (devin-state#92).
- Flag-operand boundaries (devin-state#92): a value beginning with
  `-X` after a secret flag is the *next* option, not an operand —
  every tool-scoped flag arm now rejects a flag-shaped operand, so
  `ldapadd -w -D cn=admin -w realpw` reaches the real `-w` instead
  of masking `-D`, and `http --auth-type=basic --auth u:p` no
  longer matches `--auth` as a prefix of `--auth-type` (the real
  credential flag still masks).
- expect/assignment disambiguation (devin-state#92): `expect
  "Password:" ; send "v"` no longer treats the quoted prompt as a
  `name: value` pair (quote symmetry around the key is required),
  so only the sent secret masks and the `; send` structure
  survives; `send -- "v"` is now accepted as the same carrier.
- `grep -pw`/`git grep -Pw` false positive closed (devin-state#92):
  the generic `-pw` arm is scoped to quoted subcommand spans
  (`kadmin -q "addprinc -pw p u"`), and a second `kadmin -w`
  anchored arm covers a password flag trailing the `-q` subcommand.
- `gh secret set`/`gh variable set` option gap is deterministic now
  — the bare gap alternative excludes quote characters so repeated
  quoted fragments can no longer repartition exponentially on a
  line with no `-b`/`--body` (ReDoS; devin-state#92).
- `;` boundary fixed both ways (devin-state#92): oracle-style
  `user/pass@svc` credspecs now accept `;` as a terminator so
  `sqlplus scott/pw; echo hi` masks the password, while the
  redis.conf (`requirepass`/`masterauth`), slapd (`rootpw`/
  `olcRootPW`) and mail-rc (`password pw`) arms treat `;` as
  literal password content — `requirepass hunter;2` masks `hunter;2`
  whole instead of leaking the `;2` tail.
- More credential carriers (devin-state#92): single-dash long flags
  (`boundary -password`, `vault -token`, `dsmod`/`dsadd -pwd`,
  PowerShell `-Password`) via a `-flag` arm that keeps bundled flags
  like `gcc -pass-exit-codes` out; `kubectl --from-literal=k=v`
  with an arbitrary key name; `npm set //host/:_auth` short form;
  `rabbitmqctl add_user` positional; `printf 'NAME=%s' v` (the
  argument, not the format placeholder); and `net use *` with the
  bare-asterisk drive form.
- Escaped whitespace inside config secrets (devin-state#92): the
  redis.conf/slapd/mail-rc bare-value arms now consume `\x` escape
  pairs, so `requirepass hunter\ secret` masks the whole password
  instead of stopping at the backslash.
- Quoted oracle credspecs (devin-state#92): `sqlplus "scott/pw;2"@db`
  now masks the password through the closing quote — inside quotes
  `;` is literal password content, while the unquoted arm still
  stops at shell separators.
- kubectl literal scoping (devin-state#92): the arbitrary-key
  `--from-literal` arm now requires `kubectl create secret` (any
  subtype) and captures the whole contiguous flag run including
  quoted values — ConfigMap literals such as
  `--from-literal=REGION=us-east-1` are ordinary data again.
- `printf 'NAME=%s\n' v` masks the argument even when format text
  follows the conversion specifier, and the pre-name format text
  excludes `=` so mixed placeholder lists do not bind the wrong
  argument (devin-state#92).
- `rabbitmqctl add_user` accepts a quoted username
  (`"first last"`), and the single-dash flag arm covers PowerShell
  `-Credential` (devin-state#92).
- More tool-scoped carriers (devin-state#92): SNMPv3 `-A`/`-X`
  passphrases (one anchored arm each so both mask on one line);
  spaced-or-glued `-p` for mongo/mongosh/beeline/snowsql/cqlsh/
  cypher-shell/rdesktop; `mosquitto_* -P` (lowercase `-p` stays a
  port); `openssl enc -k`/`-K`/`-iv`; `influx -t`; and
  `etcdctl user add u:p`. The `--flag` arm now tolerates dotted
  names like `arangosh --server.password`.
- `conan` `-p` password flag (with `-pr`/`--profile` kept out) and
  `vault`/`bao`/`openbao write` — the whole contiguous `k=v` run
  after the path is secret material (devin-state#92).
- kubectl `--from-literal` review round (devin-state#92): the bridge
  from `create secret` no longer crosses `;`, `|`, or `&`, so a
  `create configmap` literal on the next command is not attributed
  to the secret; global flags before `create` (`--context`,
  `-n/--namespace`) are tolerated; the captured run tolerates
  ordinary options between literals so a later literal cannot leak;
  and quoted literal values (`--from-literal=k="v"`) mask while
  keeping their quotes.
- `printf` cred binds capture the whole argument run after the
  format string, so a second credential placeholder (`K=%s K2=%s`)
  cannot leave its argument visible and a non-credential conversion
  before the cred bind (`x %s API_KEY=%s`) cannot mask the wrong
  argument (devin-state#92).
- `rabbitmqctl add_user` accepts quoted usernames containing spaces
  and escaped quotes (`"fi\"rst last"`) without mistaking part of
  the username for the password (devin-state#92).
- `openssl` secret flags are scoped to `enc` (so
  `openssl req -new -key` keeps its option) and split into
  independent `-k`/`-K`/`-iv` arms so every operand on one command
  masks (devin-state#92).
- `etcdctl user add "u:p"` quoted arguments keep their closing
  quote outside the capture so the command still parses
  (devin-state#92).
- The `conan -p` bridge stays inside one shell command, so
  `conan install . && ssh -p 2222 host` keeps the SSH port
  (devin-state#92).
- `vault`/`bao`/`openbao write` tolerates options before the path
  (`-format=json`) and empty fields (`blank=`) inside the `k=v`
  run, so a later secret pair cannot leak (devin-state#92).
- Positional secret carriers (devin-state#92):
  `ansible-vault encrypt_string` (with value-flags like
  `--name`/`--stdin-name` consuming their argument so the flag
  value is not mistaken for the secret), `vault`/`bao`/`openbao`
  `login` tokens (with `-method`/`-path` flag args), `ssh-keygen`
  `-P`/`-N` passphrases, and `smbclient //share password`.
- `kubectl create secret` literals mask individually through a
  `SUBMASK_PATTERNS` engine hook (devin-state#92): each
  `--from-literal=k=v` gets its own tag so intervening flags
  (`--dry-run=client`, `--type`, `-n ns`) are preserved instead of
  being absorbed into one redaction span, global flags before
  `create` no longer break the anchor, and `create configmap`
  literals stay plain data. The rewritten pattern is linear-time —
  no atomic groups, so Python 3.10 stays supported.
- `printf`/`echo`-style argument runs stop before shell
  redirection (`>`, `>>`, `<`, `2>`…) and `#` comments, so
  `printf 'K=%s' v >> .env` masks `v` without eating the
  redirect (devin-state#92).
- Quoted option arguments and attached `=` forms no longer hide
  positional secrets (devin-state#92): `ansible-vault --name
  "two words"`, `vault login -path "a b"` and `-format=json`,
  `conan remote login … "a&b" -p x` (a quoted `&|`/`;` can no
  longer stop the gap mid-command), and `smbclient` with quoted
  `//share` or options before the share (`-U alice`, `-N`).
- Bare positional credential tokens (devin-state#92): `snyk auth`,
  `wandb login`, `ngrok [config add-]authtoken`, `cloudflared
  service install`, `zrok enable` — value-taking flags
  (`--host`, `--log-level`, zrok `-d`/`-i`…) consume their
  argument so the flag value is not mistaken for the token, and
  flag vocabulary is scoped per tool so an unknown `-d` cannot
  swallow an ngrok token.
- Tool-scoped credential flags (devin-state#92): `az login`/
  `surreal`/`airflow users create` `-p` (lower-case, plus glued
  `-pX` forms), OpenStack `swift -K`, `codecov -t`, `cypress
  --key`, `pulsar-admin --auth-params`, `atlas|mongocli
  --privateKey` — each arm accepts spaced, `=`-attached, glued,
  and quoted values while a `(?!-[-\w])` lookahead keeps a
  dangling flag from consuming the next flag.
- Positional credential pairs (devin-state#92): `confluent
  api-key store KEY SECRET`, `emqx ctl admins passwd USER PASS`
  mask only the second operand, leaving the key/user intact.
- Env-style space-separated setters (devin-state#92): `hardhat
  vars set`, `sst secrets set`, `arc env -e` join `cf set-env`/
  `netlify env:set`/`render env:set`.
- `nomad var put <path> k=v` masks the whole `k=v` run like the
  `vault write` arm (devin-state#92).
- More space-separated setters (devin-state#92): `dotenv set`,
  `railway variables set` join the credential-name-gated arm;
  secret-store writes (`fly|flyctl secrets set`, `sst secrets
  set`, `infisical secrets set`, `keybase secret set`) mask the
  value whatever the name's shape.
- kubectl literal boundaries (devin-state#92): a
  `--from-literal=` inside a quoted option
  (`--note="--from-literal=x"`) no longer masks mid-quote, an
  unquoted `#` opens a comment so literal text after it stays
  plain, a prior `<REDACTED:…>` tag inside one literal cannot
  hide later literals (tag-gap rescan reuses the literal
  sub-regex once the parent arm proved `create secret`), and a
  `\`-newline continuation keeps the tail on one command.

## [0.2.5] - 2026-10-23

### Fixed

- The tag-gap fragment rescan no longer inherits the `env_assignment`
  `^` anchor (devin-state#82). After a closed `<REDACTED:…>` tag split a
  greedy match, a fragment beginning with non-key text —
  `API_KEY=<tag>suffix OTHER_TOKEN=raw` — left the tail assignment raw.
  The rescan now uses a de-anchored variant (`\s*` + `(?<!\w)`
  lookbehind) scoped to fragment rescanning only; the anchored pattern
  is unchanged for ordinary matching. Reunifies behavior with the
  TypeScript port, which shipped the equivalent fix in
  devin-powerups#223 — the port-only divergence case can now join the
  parity corpus.

## [0.2.4] - 2026-10-21

### Fixed

- `redact_text`/`scan_text` no longer drop a whole match when it
  contains a `<REDACTED:…>` tag (devin-state#66). Greedy patterns reach
  past the tag — `env_assignment` swallows the rest of the line — so
  `API_KEY=<REDACTED:x> OTHER_TOKEN=raw` previously left `OTHER_TOKEN`'s
  value raw and unreported (it can never match separately: the pattern
  is `^`-anchored). Only the tag's own span is now treated as prior
  output: each tag-free fragment of the match is re-scanned with the
  same pattern. Rescan stays safe inside code: `env_assignment`
  candidates keep the `_looks_like_code_assignment` suppression per
  fragment and are dropped when an unclosed bracket or dangling quote
  shows they sit inside a literal/container — so
  `KEY=["<tag> TAIL=v"]` and `KEY='abc<tag>def'` are left untouched
  rather than having their delimiters eaten. A `<REDACTED:` prefix with
  no closing `>` is malformed, not a real tag, and keeps the old
  whole-match skip.

### Added

- `devin-redact cflite-promote`: promotes ClusterFuzzLite minimized crash
  artifacts into the checked-in regression corpus at `fuzz/corpus/`
  (`new devin_redact.cflite` module). Sources: `--crashes-dir` for an
  already-unpacked artifact dir (recursive discovery), or `--run-id` to
  fetch a workflow run's artifacts via `gh run download` (`--artifact`
  narrows to named artifacts). Each crash is stored as
  `crash-<sha256>` — the name is the dedup key — and provenance (source
  artifact, run id, size, timestamp) is recorded in `manifest.json`.
  Validation is bounds-only but fail-loud: non-regular, empty or
  oversized (>1 MiB, `--max-bytes`) artifacts land in `rejected` and
  exit 1 rather than being silently skipped; usage/hard errors exit 2.
  `--dry-run` reports without writing. `tests/test_fuzz_corpus.py`
  replays every corpus entry through the atheris consumption the fuzz
  target uses and enforces manifest/disk integrity.
- `cflite-promote` review hardening (devin-state#78): the corpus
  manifest records the artifact-relative `source` (e.g.
  `fuzz-crashes-linux/crash-123`) instead of a dead temp path;
  dedup counts only validated `crash-<sha256>` entries so seed/notes
  files can't swallow a crash; on-disk crash entries missing from the
  manifest are reconciled into it; candidates are scanned with
  `engine.scan_text` and credential-shaped crashes are rejected unless
  `--allow-sensitive`; `--max-bytes` above the corpus bound exits 2
  instead of creating a corpus its own integrity check rejects. The
  `atheris` dev extra (linux marker) lets standard CI replay the
  corpus instead of import-skipping it.

## [0.2.3] - 2026-10-20

### Fixed

- Ship the `devin-redact-mcp` console script in the wheel: the entry
  point has been declared in `[project.scripts]` since the MCP server
  landed, but the published 0.2.2 wheel predates it (its
  `entry_points.txt` ships only `devin-redact`, and the metadata has
  no `mcp` extra). This release also publishes the `mcp` extra the
  plugin manifest's `uvx --from 'devin-redact[mcp]'` launch needs.
- `devin-redact-mcp` exits with a one-line install hint when the `mcp`
  extra is missing instead of dumping a traceback; startup
  `ImportError`s from `.run()` keep their traceback.
- `gate --staged` + published pre-commit hook: the hook now runs
  `devin-redact gate --staged`, which scans each path's blob in the git
  index (`:0:<path>`) via the new `devin_redact.staged` /
  `engine.scan_blobs` path. Previously the hook scanned working-tree
  files, so a secret staged and then edited or deleted out of the
  worktree bypassed the gate while still shipping in the commit. Paths
  with no staged blob (staged deletions, never-added files) are skipped;
  an unreadable index entry fails closed (exit 2).
- `env_assignment` literal detection now parses the right-hand side with
  `ast.literal_eval` instead of a quote-prefix heuristic — the bare
  `("secret")` fix from 0.2.1 now also covers nested parens, `r`/`b`/`u`
  prefixes, triple quotes, implicit concatenation (`("a" "b")`),
  trailing `#` comments and one-element tuples (`("x",)`). Dynamic
  expressions — calls, f-strings, comprehensions, conditionals and real
  containers — stay suppressed.

### Changed

- README gains the generated `Part of the DEVIN ecosystem` block
  (track/nature/audience/interface rendered from the registry).
- Test fixtures are allowlisted via `.secrets-scan-allow`
  (`path sha256=<hash>` entries) now that the shared secrets-scan drops
  its blanket `fixtures` directory exclusion.

- `labeler.yml` is now a thin caller of the shared reusable workflow in `devin-powerups` (`@v1`); PR labeling behavior is unchanged.

- Docs: export da raiz Zscaler no guia corporate-windows agora pede PEM — "Base-64 encoded X.509" no wizard de export ou `certutil -encode` após `Export-Certificate` (que gera DER) — e distingue `certmgr.msc` (store do usuário) de `certlm.msc` (store da máquina); a receita offline instala `setuptools`+`wheel` antes do `--no-build-isolation`.

- Install section now recommends pypi `uv tool install devin-redact` as the primary route, with `pipx`/source installs documented as alternatives.
- `llms.txt` no longer states a hard-coded ecosystem size; the registry owns the count.
- Platform guides and the README install command no longer pin a release; they install the latest published version.

### Added

- `ghcr.io/icaro0310/devin-redact` container image: the `devin-redact`
  CLI on `python:3.12-slim` running as a non-root user, published after
  each `redact-v*` release.
- `devin_redact.paths`: default `sessions.db` discovery matching the
  ecosystem convention (`%APPDATA%\devin\cli\sessions.db`,
  `~/Library/Application Support/…`, `$XDG_DATA_HOME`/`$XDG_CONFIG_HOME`/`~`
  fallbacks) — same candidate order as `devin-history`.
- CLI `sessionend-scan`: the `scan` invocation shaped for the
  `SessionEnd` hook (RD-1). Scan-only, bounded to the auto-detected
  default `sessions.db` (optional explicit path), prints one compact
  verdict line (`devin-redact: findings=N publication_status=X`), exits
  0 even on `BLOCKED` — non-zero (2) only on hard error. Registration
  documented in `docs/HOOKS.md` with the `hooks.json` entry for the
  planned `devin-powerups` hook dispatcher.
- Read-only adapters: `devin_redact.mcp_server` MCP server
  (`redact_scan` + `redact_verify_publish`, `devin-redact-mcp` entry
  point, `mcp` extra), Devin skill and `adapters/` plugin root. Session
  scans honor a `sessions.db` passed via `scan_paths`, report absent
  sessions as `no_session` instead of `CLEAN`, and surface missing scan
  targets as `missing_paths`/`no_targets` rather than silently scanning
  zero files.
- CLI `gate`: machine gate for pipelines like `devin-history` (RD-4).
  Prints just the `publication_status` word; exits 0 for CLEAN/REVIEW,
  1 for BLOCKED, 2 on error.
- Cross-chunk scan pass (RD-2): on `sessions.db`-shaped stores, re-scans
  concatenations of adjacent same-session payloads —
  `tool_call_json`+`tool_call_update_json` of the same `tool_call_state`
  row, adjacent `tool_call_state`/`message_nodes` rows, and streaming
  parts inside one payload — so secrets split across two chunks are
  reassembled and reported at the earlier rowid with
  `kind="cross-chunk"`. Bounded: adjacent pairs only, same session only,
  full pattern matching only after a cheap boundary pre-filter.
  Detection-only: `redact` does not rewrite split secrets back into two
  halves.
- CLI `session-end`: per-session SessionEnd hook (RD-1). Resolves the
  just-ended session — `--session-id` → `{"session_id": …}` on stdin →
  `DEVIN_SESSION_ID` → most recently active in `sessions.db` — scans only
  that session's rows via `engine.scan_session()` and writes the verdict
  to a side file (`<data-dir>/redact/<session-id>.json`; `--data-dir`,
  `DEVIN_REDACT_DATA_DIR` and `--out` override). Never writes into any
  Devin store or transcript; fail-soft — unresolvable sessions produce a
  `SKIPPED` verdict and exit 0, only usage errors exit 2.
- CLI `verify-publish`: publication gate for `devin-history` export
  directories (RD-4). Enumerates exported sessions from `index.json`/
  `index.md` or the `<YYYY-MM-DD>_<session-id>.<ext>` layout, extracts
  each `session_id`, scans every file read-only and reports per-session
  verdicts. Cross-references `session-end` side files — a `BLOCKED` hook
  verdict beside a `CLEAN` export is a warning that holds the overall
  verdict at `REVIEW`. Exits 0 only when the overall verdict is `CLEAN`.
- Session-scoped scanning: `engine.scan_session(db, session_id)` filters
  every session-attributed table (`session_id` column, or `sessions.id`),
  including the cross-chunk pass; the `sessions` metadata row itself is
  excluded so clean sessions stay `CLEAN`.
- Cross-chunk pre-filter hardened (RD-2): a token-run of secret length
  spanning a payload boundary now triggers the reassembly scan, so a
  secret split at *any* byte offset — including 1-char fragments on
  either side — is detected; context pre-filters relaxed to catch
  `Bearer`/`KEY=`/`pairing code` hugging the edge.
- Tests: split-secret fixtures (adjacent message nodes, adjacent and
  within-row tool calls, streamed content parts), cross-session and
  non-adjacent negatives, every-offset split sweep, `sessionend-scan`/
  `gate`/`session-end` exit codes and verdict contracts, `verify-publish`
  over md/json export layouts, path auto-detection. 100 tests green.

## [0.2.2] - 2026-10-11

### Fixed

- `__version__` now matches the published artifact: the 0.2.1 wheel on
  PyPI self-reports 0.2.0 (built from an unmerged branch before the
  verify gate existed). This release exists so the index carries a
  wheel whose metadata and self-report agree.

## [0.2.1] - 2026-10-10

### Fixed

- `env_assignment` no longer fires when the matched name is bound to a
  code expression — `_STRUCTURAL_KEYS = frozenset({...})`,
  `TOKEN_RE = re.compile(...)`, `SECRET_PATTERNS = [...]`. The pattern
  anchors on KEY/SECRET/TOKEN-carrying names, which made any repo
  holding scanner configs, env parsers or policy generators (including
  this package's own source and devin-janitor's regexes) gate BLOCKED.
  Suppression covers only right-hand sides that are container literals
  or calls — shapes an env value can never take; bare and quoted values
  still flag, so private constants holding real secrets remain caught.
  Applies to scan and redact identically via `_iter_matches`.

- `__version__` now matches the package version (the 0.2.1 wheel had shipped self-reporting 0.2.0).
- PyPI publish workflow verifies the wheel's self-reported `__version__` against `pyproject.toml` before upload (`--no-deps` install into an isolated target).
- Release workflow passes `github.ref_name` through `env:` instead of interpolating it into `run:` shell source.

### Added

- GHCR image `ghcr.io/icaro0310/devin-redact` tagged `<version>` + `latest` (linux/amd64 + linux/arm64); the image installs the published wheel, never the checkout.

## [0.2.0] - 2026-09-29

### Added

- `devin_redact.semantic`: tool-call semantic layer. Parses
  `tool_call_state.tool_call_json` `rawInput` and flags the associated
  `tool_call_update_json` output for redaction when the command/read
  targets a known-sensitive file (`.env*`, `credentials*`, `*.pem`,
  `~/.ssh`, `~/.aws`, …) — even when no pattern matches the output.
  Findings carry `kind="semantic-context"`.
- `engine.redact()` real implementation: replaces secret spans with
  `<REDACTED:sha256prefix>` (keeping `KEY=` prefixes for `.env`
  assignments), decodes/rewrites JSON cells leaf-wise so structure stays
  valid, and wholesale-redacts output payloads of sensitive reads while
  preserving structural keys (`type`, `mimeType`, `toolCallId`, …).
- Write path safety: dry-run by default; in-place requires
  `--apply --i-know-this-is-irreversible`; mandatory `.bak` sibling
  backups; DB updates in a single transaction; post-redact open +
  `integrity_check` with backup restore on failure.
- CLI `verify`: exits 0 only when `CLEAN`, 1 otherwise with
  `PUBLICATION STATUS: …` + per-category summary; `--json` for the full
  report.
- Idempotent redaction: `<REDACTED:…>` tags are never re-matched or
  re-redacted; `scan` ignores already-redacted values.
- Fixture corpus extended with a semantic-layer case (`cat .env` output
  with no pattern-shaped secret) and a benign `ls -la` negative control.
- Tests: redact-on-copy (DB still opens, planted fingerprints gone,
  edits logged), transaction rollback on induced failure, semantic
  flagging, `verify` exit codes both ways, text/JSON redaction
  idempotency. 23 tests green.

## [0.1.0] - 2026-09-29

### Added

- `devin_redact.patterns`: detection patterns for API keys (OpenAI/Stripe/
  AWS/Google/Slack), bearer tokens and JWTs, GitHub tokens (`ghp_`, `gho_`,
  `ghu_`, `ghs_`, `ghr_`, `github_pat_`), PEM private keys, `.env`-style
  assignments, Devin pairing codes, emails and absolute user paths.
- `devin_redact.engine.scan()`: read-only scan over text files and SQLite
  session stores, decoding JSON cells (including `tool_call_json`,
  `tool_call_update_json`, `chat_message`) so secrets in tool-call inputs
  *and* outputs are found. Returns the deterministic JSON report contract
  from `docs/SPEC.md` §6 (`files_scanned`, `secrets`, `emails`,
  `absolute_paths`, `project_names`, `publication_status`, `findings`).
- `devin_redact.engine.redact()`: dry-run only stub for M1 (`apply` raises
  `NotImplementedError`).
- CLI `devin-redact` with `scan` (prints/`--report` JSON) and `redact`
  (dry-run); `verify` stubbed for M2.
- Fixture corpus under `tests/fixtures/` with planted synthetic secrets:
  `sessions.db` (generated by `generate_sessions_db.py`, mirrors the real
  schema), `memories.jsonl`, `export.md`, `.env`, `benign.txt`.
- Tests: recall over the planted corpus (sha256 fingerprints), benign text
  produces zero findings, scan idempotency/read-only guarantees, DB opens
  after scan, CLI smoke.
- `docs/SPEC.md`: canonical English translation of `SPEC.pt-BR.md`.
- Initial scaffold from `devin-repo-template`.
