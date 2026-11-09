# Odoo IT Audit Script

Read-only evidence collector for IT audits of Odoo databases hosted on **Odoo.sh** (it also works on self-hosted Odoo).
It gathers configuration, user access, change-management and log evidence in one run and packages it with SHA-256 hashes for evidence integrity.

**Author:** Nimrod Moyo, BSc, MSc, CISSP, CEH, CC

---

## What it collects

| Area | Evidence |
|---|---|
| **Configuration** | `odoo.conf` with secrets redacted (plus hash of the original), system parameters, companies, accounting lock dates and audit-trail settings, journal hash-lock status |
| **Access** | All users with groups, 2FA status, last login and custom rights; privileged-access matrix; API keys (names/owners only); login history; mail, LDAP and OAuth configuration |
| **Customisations** | Custom modules (identified by code location), custom/Studio fields, non-standard views, server actions (Python code exported), automation rules, scheduled actions, ACLs and record rules tagged *standard / custom module / Studio / created in UI* |
| **Source code** | Remote, branch, HEAD, all commits since `--since` with changed files and SOW/ticket-reference check, uncommitted files on the server, shallow-clone detection, SHA-256 baseline of every custom-module file |
| **Logs** | Odoo.sh logs including rotated `.gz` files: login success/failure with IP, module install/upgrade actions with user, access-denied errors, coverage window |

`SUMMARY.md` lists automated **points to note**, for example admins without 2FA, vendor or generic admin accounts, uncommitted server code, UI-created automation rules, journals without hash lock, missing lock dates and log gaps. These are indicators for follow-up, not audit conclusions.

## Safety

- All database queries run in a **`READ ONLY` transaction** that is rolled back at the end. No data is changed (verified by comparing database dumps before and after a run).
- Passwords, tokens, API keys and credentials in URLs are redacted before anything is written.
- Runs at lowered CPU priority, with statement and lock timeouts, row caps and an overall time budget.
- A lock file prevents concurrent runs.

## Resilience

- Retries transient failures with exponential backoff; non-recoverable errors fail fast.
- On a statement timeout it doubles the timeout and halves row limits, then retries.
- Reconnects automatically if the database connection drops.
- Each step is isolated: one failure never stops the rest. Missing modules or tools are marked *not applicable*.
- Detects the Odoo source location, configuration file, database, log folders and version-specific field names.

## Quick start

Open **Odoo.sh → your project → Branches → Production → Shell** and paste one of the commands below. This needs admin access to the Odoo.sh project, so it should be run by the client or their partner, with the auditor observing.

Change `--since` to the start of the period under review.

### Option 1: download, verify and run (recommended for audit evidence)

```bash
cd ~ && curl -fsSLO https://raw.githubusercontent.com/nimrodzw/Odoo-IT-Audit-Script/2c31d9e842b8269565bcd4c7cf79cf07390b1bd1/odoo_sh_audit_collector.py
sha256sum odoo_sh_audit_collector.py
python3 odoo_sh_audit_collector.py --since 2026-01-01
```

The `sha256sum` output must be:

```
20d7a55afaf277c9b03ade21b48458de92c47b65e9470a6960db835dc09a2a30
```

The run also records the script's hash in `environment.json`, so the evidence package shows exactly which version produced it.

### Option 2: run directly from GitHub, nothing saved

```bash
curl -fsSL https://raw.githubusercontent.com/nimrodzw/Odoo-IT-Audit-Script/2c31d9e842b8269565bcd4c7cf79cf07390b1bd1/odoo_sh_audit_collector.py | python3 - --since 2026-01-01
```

### Option 3: no curl available

```bash
python3 -c "import urllib.request as u; exec(compile(u.urlopen('https://raw.githubusercontent.com/nimrodzw/Odoo-IT-Audit-Script/2c31d9e842b8269565bcd4c7cf79cf07390b1bd1/odoo_sh_audit_collector.py').read(), 'odoo_sh_audit_collector.py', 'exec'))" --since 2026-01-01
```

With options 2 and 3 the script hash is recorded as `n/a (run from stdin)`. Use option 1 when the hash matters.

### Collect the results

The evidence package is written to `~/odoo_audit_evidence/evidence_<timestamp>.zip`, with a `.sha256` file alongside it.

```bash
ls -lh ~/odoo_audit_evidence/
```

Download the zip from the Odoo.sh **Editor** tab (right-click the file → Download) or with `scp`. Then remove everything from the server:

```bash
rm -rf ~/odoo_audit_evidence ~/odoo_sh_audit_collector.py
```

The URLs above are pinned to the exact commit of v1.0.1 (`2c31d9e`), so the code that runs can't change unless the URL changes.

### Options

| Option | Default | Purpose |
|---|---|---|
| `--since YYYY-MM-DD` | 1 Jan of current year | Start of the period for commits, logins, logs and change flags |
| `--db NAME` | auto-detected | Database name |
| `--config PATH` | auto-detected | Odoo configuration file |
| `--out DIR` | `~/odoo_audit_evidence` | Output folder |
| `--skip a,b` | – | Skip steps (e.g. `db_views,logs`, or `db` to skip all database steps) |
| `--ticket-pattern REGEX` | generic | Regex for SOW/ticket references in commit messages |
| `--retries N` | 3 | Attempts per step |
| `--timeout SEC` | 60 | SQL statement timeout (adapts upward on timeouts) |
| `--max-rows N` | 100000 | Row cap per export (adapts downward on timeouts) |
| `--log-mb N` | 50 | Maximum MB read per log file |
| `--max-minutes N` | 30 | Overall time budget |
| `--no-zip` | – | Leave output as a folder |

The exit code is `0` when all steps succeed and `1` when any step fails. Details are in `collection_status.csv` and `errors.log`.

## Output files

| File | Content |
|---|---|
| `SUMMARY.md`, `observations.csv` | Environment overview, points to note, step status |
| `users.csv`, `groups.csv`, `privileged_access_matrix.csv`, `api_keys.csv`, `login_history_db.csv` | Access |
| `modules_installed.csv`, `modules_custom.csv`, `custom_fields.csv`, `views_custom_or_ui.csv`, `server_actions_custom_or_ui.csv`, `server_action_code/`, `automation_rules.csv`, `scheduled_actions.csv`, `access_control_lists.csv`, `record_rules.csv` | Customisations |
| `git_repositories.csv`, `git_commits_since.csv`, `git_files_changed_since.csv`, `custom_code_file_hashes.csv` | Source code |
| `odoo_conf_redacted.conf`, `system_parameters.csv`, `companies_and_lock_dates.csv`, `journals.csv`, `mail_servers.csv` | Configuration |
| `log_inventory.csv`, `log_events.csv`, `log_levels.csv`, `logs/` | Logs |
| `MANIFEST.json` | SHA-256 of every file in the package |

## Requirements

- Python 3.8+ and the Odoo Python environment (already present on Odoo.sh)
- `git` on the path for the source-code steps (optional)
- Tested on Odoo 18.0 / PostgreSQL 16. Field names are detected at run time, so other recent versions should also work.

## Notes

- Odoo.sh keeps logs for a limited time. For full-period log evidence, export logs regularly.
- Odoo keeps only recent `res_users_log` entries per user, so database login history is limited. The server logs complement it.
- Output contains personal data (user names, emails, IP addresses). Handle it under the engagement's data-handling requirements.
