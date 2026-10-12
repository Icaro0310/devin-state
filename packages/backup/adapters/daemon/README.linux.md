# devin-backup daily — systemd user timer (Linux)

> New units — the 7-day no-silent-failure observation window started
> 2026-10-12 and has not completed; see [README.md](README.md).

- **`devin-backup-daily.timer`** runs the service daily at 03:30 with
  `Persistent=true` — a missed slot (suspend, powered off) catches up at
  next activation instead of silently skipping a backup.
- **`devin-backup-daily.service`** (`Type=oneshot`) runs
  `devin-backup create` — the same command you run by hand.

The service is hardened: `NoNewPrivileges`, `PrivateTmp`,
`ProtectSystem=strict`, with writes whitelisted to the three autodetect
candidates for the backups dir (`~/.local/share/devin/backups`,
`~/.config/devin/backups`, `~/devin/backups`). Reads stay open — a
snapshot has to read every Devin store, including credentials-bearing
ones (use `devin-backup create --exclude-secrets` if the backups dir is
less trusted; see the package README).

## Install

```bash
mkdir -p ~/.config/systemd/user
cp devin-backup-daily.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now devin-backup-daily.timer
```

If `devin-backup` is not under `~/.local/bin` or the system prefixes,
extend `Environment=PATH=...` in the service (`uv tool dir` /
`pipx environment` show where the CLI landed).

Keeping snapshots elsewhere (`DEVIN_BACKUP_DIR` or a mounted drive)?
Add that path to `ReadWritePaths=` or the unit fails read-only.

The canonical alternative — `devin-backup install --backend cron` — adds
a tagged `@daily` crontab line instead of these units; do not enable
both or you get two snapshots a day.

## Smoke check — did it run without silent failure?

```bash
# Timer armed:
systemctl --user list-timers devin-backup-daily.timer

# Run it now and inspect:
systemctl --user start devin-backup-daily.service
journalctl --user -u devin-backup-daily.service -n 30 --no-pager
devin-backup list           # newest snapshot should carry today's date
devin-backup verify <dir>   # integrity check on that snapshot
```

## Headless check

`./verify.sh` in this directory lints the units (`systemd-analyze
verify` when available), parses the task XML, and cross-checks the ps1
scripts — the same checks `tests/test_daemon_adapter.py` runs in CI.

## Uninstall

```bash
systemctl --user disable --now devin-backup-daily.timer
rm ~/.config/systemd/user/devin-backup-daily.{service,timer}
systemctl --user daemon-reload
```

Existing snapshots under the backups dir are left in place.
