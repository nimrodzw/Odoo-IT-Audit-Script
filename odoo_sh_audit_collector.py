#!/usr/bin/env python3
"""
Odoo.sh IT audit evidence collector
Author: Nimrod Moyo, BSc, MSc, CISSP, CEH, CC

Read-only collection of configuration, access, change and log evidence from an Odoo.sh branch.
Run from the Odoo.sh shell (or SSH) of the branch under review, normally Production:

    python3 odoo_sh_audit_collector.py --since 2026-01-01

Options: --db NAME  --config PATH  --out DIR  --since YYYY-MM-DD  --skip step1,step2
         --ticket-pattern REGEX  --retries N  --timeout SEC  --max-rows N  --log-mb N  --max-minutes N  --no-zip

All database queries run inside a READ ONLY transaction that is rolled back at the end.
Secrets (passwords, tokens, keys) are redacted before anything is written.
"""
import argparse
import configparser
import contextlib
import csv
import datetime as dt
import getpass
import gzip
import hashlib
import json
import logging
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys
import time
import traceback
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

VERSION = "1.0.1"
SECRET_KEY_RE = re.compile(
    r"(pass(word|wd)?|secret|token|api_?key|private|credential|enterprise_code|signature|_key$|^key$|dsn)", re.I)
URL_CRED_RE = re.compile(r"(https?://)([^/@\s]+)@")
LOG_LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ (\d+) (\w+) (\S+) ([\w.\-]+): (.*)$")
LOG_EVENTS = {
    "login_success": re.compile(r"Login successful for db:(?P<db>\S+) login:(?P<login>.+?) from (?P<ip>\S+)"),
    "login_failed": re.compile(r"Login failed for db:(?P<db>\S+) login:(?P<login>.+?) from (?P<ip>\S+)"),
    "module_action": re.compile(r"ALLOW access to module\.(?P<action>\w+) on \[(?P<modules>.*?)\] to user (?P<login>.+?) #?(?P<uid>\d+)? via (?P<ip>\S+)"),
    "module_loading": re.compile(r"(updating modules list|loading \d+ modules|\d+ modules loaded|Modules loaded|init db|module (?P<module>\w+): (creating|updating|loading))", re.I),
    "access_denied": re.compile(r"(Access ?Denied|AccessError|access denied)", re.I),
}
DEFAULT_TICKET_PATTERN = r"(\b[A-Z]{2,6}[-_]?\d{2,}(\.\d+)?\b|#\d{3,}|(?i:\bSOW\b|ticket|task[-_ ]?\d+))"
GENERIC_LOGIN_RE = re.compile(r"^(admin|administrator|test|tester|demo|support|user|guest|it|helpdesk|api|integration)(@|$|\d)|test|support|admin", re.I)
PRIVILEGED_GROUPS = {
    "base.group_system": "Settings (Administrator)",
    "base.group_erp_manager": "Access Rights",
    "base.group_no_one": "Technical Features",
    "account.group_account_manager": "Accounting Administrator",
    "account.group_account_user": "Accountant",
    "account.group_account_invoice": "Invoicing",
    "sales_team.group_sale_manager": "Sales Administrator",
    "purchase.group_purchase_manager": "Purchase Administrator",
    "stock.group_stock_manager": "Inventory Administrator",
    "point_of_sale.group_pos_manager": "PoS Administrator",
    "base.group_multi_company": "Multi-company",
}
STD_AUTHOR_RE = re.compile(r"odoo s\.?a\.?|openerp", re.I)


class Skip(Exception):
    pass


class Run:
    def __init__(self, args):
        self.args = args
        self.started = dt.datetime.now()
        self.deadline = time.time() + args.max_minutes * 60
        self.scale = 1.0
        self.timeout = args.timeout
        self.ticket_re = re.compile(args.ticket_pattern)
        self.status = []
        self.flags = []
        self.facts = {}
        self.files = []
        self.home = Path(os.environ.get("HOME", "~")).expanduser()
        stamp = self.started.strftime("%Y%m%d_%H%M%S")
        base = Path(args.out).expanduser() if args.out else self.home / "odoo_audit_evidence"
        self.out = base / f"evidence_{stamp}"
        self.out.mkdir(parents=True, exist_ok=True)
        self.log = logging.getLogger("odoo_audit")
        self.log.setLevel(logging.INFO)
        self.log.propagate = False
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        for h in (logging.StreamHandler(sys.stdout), logging.FileHandler(self.out / "run.log", encoding="utf-8")):
            h.setFormatter(fmt)
            self.log.addHandler(h)

    @property
    def max_rows(self):
        return max(500, int(self.args.max_rows * self.scale))

    def flag(self, area, text, severity="note"):
        self.flags.append({"area": area, "severity": severity, "observation": text})

    def write_csv(self, name, rows, fields=None):
        rows = list(rows)
        path = self.out / f"{name}.csv"
        if not fields:
            fields = []
            for r in rows:
                fields.extend(k for k in r if k not in fields)
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=fields or ["no_data"], extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({k: cell(v) for k, v in r.items()})
        self.files.append(path)
        return len(rows)

    def write_json(self, name, data):
        path = self.out / f"{name}.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        self.files.append(path)

    def write_text(self, name, text):
        path = self.out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.files.append(path)


def cell(v):
    if isinstance(v, (list, tuple, set)):
        v = "; ".join(str(x) for x in v)
    if isinstance(v, (dt.datetime, dt.date)):
        v = v.isoformat()
    if isinstance(v, str):
        if len(v) > 32000:
            v = v[:32000] + " …[truncated]"
        if v[:1] in ("=", "+", "@", "\t", "\r"):
            v = "'" + v
    return v


def redact_value(key, value):
    if value in (None, "", False):
        return value
    if SECRET_KEY_RE.search(str(key)):
        return "[REDACTED]"
    return URL_CRED_RE.sub(r"\1[REDACTED]@", str(value))


def is_transient(exc):
    name = type(exc).__name__
    text = str(exc).lower()
    if any(s in text for s in ("does not exist", "authentication failed", "permission denied", "no such file")):
        return False
    if isinstance(exc, (subprocess.TimeoutExpired, TimeoutError, ConnectionError)):
        return True
    if name in ("OperationalError", "QueryCanceled", "TransactionRollbackError", "SerializationFailure",
                "DeadlockDetected", "LockNotAvailable", "InterfaceError"):
        return True
    return any(s in text for s in ("timeout", "temporarily", "could not serialize", "deadlock",
                                   "connection", "server closed", "too many clients"))


def step(run, name, fn, *a):
    if name in run.args.skip:
        run.status.append({"step": name, "status": "skipped", "attempts": 0, "seconds": 0, "detail": "--skip"})
        run.log.info("%-24s skipped (--skip)", name)
        return None
    if time.time() > run.deadline:
        run.status.append({"step": name, "status": "skipped", "attempts": 0, "seconds": 0, "detail": "time budget used"})
        run.log.warning("%s skipped: time budget used", name)
        return None
    for attempt in range(1, run.args.retries + 1):
        t0 = time.time()
        try:
            result = fn(run, *a)
            run.status.append({"step": name, "status": "ok", "attempts": attempt,
                               "seconds": round(time.time() - t0, 1), "detail": result if isinstance(result, str) else ""})
            run.log.info("%-24s ok (%s)", name, result if isinstance(result, str) else "done")
            return result
        except Skip as e:
            run.status.append({"step": name, "status": "not applicable", "attempts": attempt,
                               "seconds": round(time.time() - t0, 1), "detail": str(e)})
            run.log.info("%-24s not applicable: %s", name, e)
            return None
        except Exception as e:
            transient = is_transient(e)
            run.log.warning("%-24s attempt %d failed (%s): %s", name, attempt, "transient" if transient else "error", e)
            if "QueryCanceled" in type(e).__name__ or "statement timeout" in str(e).lower():
                run.timeout = min(run.timeout * 2, 900)
                run.scale = max(0.05, run.scale / 2)
            if not transient or attempt == run.args.retries:
                run.status.append({"step": name, "status": "failed", "attempts": attempt,
                                   "seconds": round(time.time() - t0, 1), "detail": f"{type(e).__name__}: {e}"})
                with open(run.out / "errors.log", "a", encoding="utf-8") as fh:
                    fh.write(f"--- {name} attempt {attempt}\n{traceback.format_exc()}\n")
                return None
            time.sleep(min(30, 2 ** attempt + random.random()))


def sh(cmd, cwd=None, timeout=60):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, errors="replace")
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:4])}… rc={p.returncode}: {p.stderr.strip()[:300]}")
    return p.stdout


def git(repo, *args, timeout=120):
    return sh(["git", "-c", "safe.directory=*", "-C", str(repo), *args], timeout=timeout)


def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(chunk), b""):
            h.update(b)
    return h.hexdigest()



def find_config(run):
    cands = [run.args.config, os.environ.get("ODOO_RC"), run.home / ".config/odoo/odoo.conf",
             run.home / ".odoorc", "/etc/odoo/odoo.conf", "/etc/odoo.conf", "/etc/odoo/openerp-server.conf"]
    for c in cands:
        if c and Path(c).expanduser().is_file():
            return Path(c).expanduser()
    return None


def self_hash():
    path = globals().get("__file__")
    if path and os.path.isfile(path):
        return sha256(path)
    return "n/a (run from stdin)"


def collect_environment(run):
    keep = re.compile(r"^(ODOO|PG|GIT|HOSTNAME|HOME|USER|PATH|LANG|TZ|PYTHON|VIRTUAL_ENV)", re.I)
    env = {k: redact_value(k, v) for k, v in sorted(os.environ.items()) if keep.search(k)}
    du = shutil.disk_usage(str(run.home))
    info = {
        "collector_version": VERSION,
        "collector_sha256": self_hash(),
        "run_started": run.started.isoformat(),
        "run_by_os_user": getpass.getuser(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "home": str(run.home),
        "odoo_sh_layout": (run.home / "src").is_dir() and (run.home / "logs").is_dir(),
        "disk_total_gb": round(du.total / 1e9, 1),
        "disk_free_gb": round(du.free / 1e9, 1),
        "since": run.args.since.isoformat(),
        "environment": env,
    }
    run.facts.update({k: v for k, v in info.items() if k != "environment"})
    run.write_json("environment", info)
    return f"odoo.sh layout={info['odoo_sh_layout']}"


def collect_config(run):
    path = find_config(run)
    if not path:
        raise Skip("no Odoo configuration file found")
    cp = configparser.RawConfigParser(strict=False)
    cp.read(path, encoding="utf-8")
    data = {s: {k: redact_value(k, v) for k, v in cp.items(s)} for s in cp.sections()}
    lines = []
    for s, kv in data.items():
        lines.append(f"[{s}]")
        lines.extend(f"{k} = {v}" for k, v in kv.items())
        lines.append("")
    run.write_text("odoo_conf_redacted.conf", f"; source: {path}\n; sha256 of original: {sha256(path)}\n" + "\n".join(lines))
    run.write_json("odoo_conf_redacted", {"path": str(path), "sections": data})
    opts = data.get("options", {})
    run.facts["config_path"] = str(path)
    run.facts["config_options"] = opts
    if str(opts.get("list_db", "")).lower() in ("true", "1"):
        run.flag("Configuration", "list_db is enabled (database manager screens available).")
    raw_admin = cp.get("options", "admin_passwd", fallback=None)
    if raw_admin in ("admin", "", None):
        run.flag("Configuration", "Master password (admin_passwd) is default or not set.", "high")
    return str(path)


def addons_paths(run):
    opts = run.facts.get("config_options", {})
    paths = [p.strip() for p in str(opts.get("addons_path", "")).split(",") if p.strip()]
    src = run.home / "src"
    if src.is_dir():
        paths += [str(p) for p in src.iterdir() if p.is_dir()]
    seen, out = set(), []
    for p in paths:
        rp = os.path.realpath(p)
        if rp not in seen and os.path.isdir(rp):
            seen.add(rp)
            out.append(rp)
    return out


def std_roots(run):
    roots = set()
    try:
        import odoo
        pkg = Path(odoo.__file__).resolve().parent
        roots |= {str(pkg), str(pkg.parent / "addons"), str(pkg.parent)}
    except Exception:
        pass
    for name in ("odoo", "enterprise", "themes", "design-themes"):
        p = run.home / "src" / name
        if p.exists():
            roots.add(os.path.realpath(p))
    return roots


def is_std_path(path, roots):
    rp = os.path.realpath(path)
    return any(rp == r or rp.startswith(r + os.sep) for r in roots)


def collect_git(run):
    if not shutil.which("git"):
        raise Skip("git not available")
    roots = std_roots(run)
    repos = {}
    for p in addons_paths(run) + [str(run.home / "src" / "user")]:
        if not os.path.isdir(p):
            continue
        try:
            top = git(p, "rev-parse", "--show-toplevel", timeout=30).strip()
            repos[os.path.realpath(top)] = None
        except Exception:
            for d in Path(p).glob("*/.git"):
                repos[os.path.realpath(d.parent)] = None
    if not repos:
        raise Skip("no git repositories found in addons paths")
    since = run.args.since.isoformat()
    summary, commits, files_changed = [], [], []
    for repo in repos:
        std = is_std_path(repo, roots)
        info = {"repository": repo, "standard_odoo": std}
        for key, args in {"remote": ("remote", "-v"), "branch": ("rev-parse", "--abbrev-ref", "HEAD"),
                          "head": ("rev-parse", "HEAD"), "head_date": ("log", "-1", "--format=%cI"),
                          "shallow": ("rev-parse", "--is-shallow-repository"),
                          "first_commit_available": ("log", "--reverse", "--format=%cI", "--max-parents=0")}.items():
            try:
                out = git(repo, *args).strip()
                info[key] = URL_CRED_RE.sub(r"\1[REDACTED]@", out.splitlines()[0] if key == "first_commit_available" and out else out)
            except Exception as e:
                info[key] = f"n/a ({e})"[:200]
        if not std:
            try:
                status = [l for l in git(repo, "status", "--porcelain", "--untracked-files=all").splitlines()
                          if l.strip() and "__pycache__" not in l and not l.endswith((".pyc", ".pyo"))]
                info["uncommitted_changes"] = len(status)
                if status:
                    run.write_text(f"git/{Path(repo).name}_uncommitted.txt", "\n".join(status))
                    run.flag("Change management", f"Repository {repo} has {len(status)} uncommitted/untracked file(s) on the server.", "high")
            except Exception as e:
                info["uncommitted_changes"] = f"n/a ({e})"
            try:
                info["submodules"] = git(repo, "submodule", "status", "--recursive").strip()
            except Exception:
                info["submodules"] = ""
            fmt = "%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%cI%x1f%s"
            log = git(repo, "log", f"--since={since}", f"--max-count={run.max_rows}", f"--format={fmt}", timeout=300)
            n = 0
            for line in log.splitlines():
                parts = line.split("\x1f")
                if len(parts) < 8:
                    continue
                h, parents, an, ae, ad, cn, cd, subj = parts[:8]
                commits.append({"repository": Path(repo).name, "commit": h, "is_merge": len(parents.split()) > 1,
                                "author": an, "author_email": ae, "authored": ad, "committer": cn, "committed": cd,
                                "subject": subj, "has_ticket_reference": bool(run.ticket_re.search(subj))})
                n += 1
            info["commits_since"] = n
            try:
                names = git(repo, "log", f"--since={since}", f"--max-count={run.max_rows}", "--name-status",
                            "--format=@@%H", timeout=300)
                cur = None
                for line in names.splitlines():
                    if line.startswith("@@"):
                        cur = line[2:]
                    elif line.strip() and cur:
                        st, _, f = line.partition("\t")
                        files_changed.append({"repository": Path(repo).name, "commit": cur, "change": st, "file": f})
            except Exception as e:
                run.log.warning("file list for %s failed: %s", repo, e)
            if str(info.get("shallow")) == "true":
                run.flag("Change management", f"Repository {repo} is a shallow clone; history on the server is incomplete – obtain the full history from the hosted repository.")
        summary.append(info)
    run.write_csv("git_repositories", summary)
    run.write_csv("git_commits_since", commits)
    run.write_csv("git_files_changed_since", files_changed)
    custom_commits = [c for c in commits if not c["is_merge"]]
    unref = [c for c in custom_commits if not c["has_ticket_reference"]]
    run.facts["git"] = {"repositories": len(summary), "commits_since": len(commits), "without_reference": len(unref)}
    if custom_commits and unref:
        run.flag("Change management", f"{len(unref)} of {len(custom_commits)} commits since {since} have no SOW/ticket reference in the message.")
    authors = Counter(c["author_email"] for c in commits)
    run.facts["git"]["authors"] = dict(authors)
    return f"{len(summary)} repos, {len(commits)} commits"


def collect_code_hashes(run):
    roots = std_roots(run)
    rows, count = [], 0
    for base in addons_paths(run):
        if is_std_path(base, roots):
            continue
        for mod in sorted(Path(base).iterdir()):
            if not (mod / "__manifest__.py").is_file():
                continue
            for dirpath, dirnames, filenames in os.walk(mod):
                dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules")]
                for f in filenames:
                    if f.endswith((".pyc", ".pyo")):
                        continue
                    p = Path(dirpath) / f
                    try:
                        st = p.stat()
                        rows.append({"module": mod.name, "file": str(p.relative_to(base)), "bytes": st.st_size,
                                     "modified": dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                                     "sha256": sha256(p)})
                    except OSError as e:
                        rows.append({"module": mod.name, "file": str(p), "sha256": f"error: {e}"})
                    count += 1
                    if count >= run.max_rows:
                        run.log.warning("code hash cap reached (%d files)", count)
                        run.write_csv("custom_code_file_hashes", rows)
                        return f"{count} files (capped)"
    if not rows:
        raise Skip("no custom module directories found")
    run.write_csv("custom_code_file_hashes", rows)
    return f"{len(rows)} files"


def log_dirs(run):
    dirs = []
    logfile = run.facts.get("config_options", {}).get("logfile")
    if logfile and logfile not in ("None", "False"):
        dirs.append(Path(logfile).expanduser().parent)
    dirs += [run.home / "logs", Path("/var/log/odoo")]
    seen, out = set(), []
    for d in dirs:
        if d.is_dir() and os.path.realpath(d) not in seen:
            seen.add(os.path.realpath(d))
            out.append(d)
    return out


def tail_lines(path, max_bytes):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as fh:
        if path.suffix != ".gz":
            size = path.stat().st_size
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()
            data = fh.read()
        else:
            data = fh.read(max_bytes * 4)[-max_bytes:]
    return data.decode("utf-8", "replace").splitlines()


def collect_logs(run):
    dirs = log_dirs(run)
    if not dirs:
        raise Skip("no log directory found")
    max_bytes = int(run.args.log_mb * 1e6 * max(run.scale, 0.25))
    inventory, events, levels = [], [], Counter()
    for d in dirs:
        for p in sorted(d.iterdir()):
            if not p.is_file() or not re.search(r"\.log(\.\d+)?(\.gz)?$|\.gz$", p.name):
                continue
            st = p.stat()
            lines = tail_lines(p, max_bytes)
            first = last = None
            raw = []
            for line in lines:
                m = LOG_LINE_RE.match(line)
                if not m:
                    continue
                ts, pid, level, db, logger, msg = m.groups()
                first = first or ts
                last = ts
                levels[(p.name, level)] += 1
                for kind, rx in LOG_EVENTS.items():
                    em = rx.search(msg)
                    if em:
                        ev = {"file": p.name, "timestamp": ts, "level": level, "database": db, "logger": logger, "event": kind}
                        ev.update({k: v for k, v in em.groupdict().items() if v})
                        ev["message"] = msg[:500]
                        events.append(ev)
                        break
                if level in ("ERROR", "CRITICAL"):
                    raw.append(line[:2000])
            inventory.append({"directory": str(d), "file": p.name, "bytes": st.st_size,
                              "modified": dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                              "bytes_read": min(st.st_size, max_bytes), "complete": st.st_size <= max_bytes,
                              "first_entry_read": first, "last_entry_read": last})
            if raw:
                run.write_text(f"logs/{p.name}.errors.txt", "\n".join(raw[-5000:]))
            dest = run.out / "logs" / (p.name if p.suffix != ".gz" else p.stem)
            dest.parent.mkdir(exist_ok=True)
            dest.write_text("\n".join(lines[-200000:]), encoding="utf-8")
            run.files.append(dest)
    run.write_csv("log_inventory", inventory)
    run.write_csv("log_events", events)
    run.write_csv("log_levels", [{"file": f, "level": l, "count": c} for (f, l), c in sorted(levels.items())])
    starts = sorted(i["first_entry_read"] for i in inventory if i["first_entry_read"])
    run.facts["logs"] = {"files": len(inventory), "earliest": starts[0] if starts else None,
                         "events": Counter(e["event"] for e in events)}
    if starts and starts[0][:10] > run.args.since.isoformat():
        if all(i["complete"] for i in inventory):
            run.flag("Logging", f"Server logs available only from {starts[0][:10]}; they do not cover the period from {run.args.since}. "
                                "Odoo.sh keeps logs for a limited time – consider exporting them regularly.")
        else:
            run.flag("Logging", f"Logs were read from {starts[0][:10]} only (capped at --log-mb {run.args.log_mb}); rerun with a higher cap for full coverage.")
    fails = [e for e in events if e["event"] == "login_failed"]
    if fails:
        top = Counter(e.get("login") for e in fails).most_common(5)
        run.flag("Access", f"{len(fails)} failed logins in available logs; most frequent: {top}.")
    mods = [e for e in events if e["event"] == "module_action"]
    if mods:
        run.flag("Change management", f"{len(mods)} module install/upgrade/uninstall actions recorded in logs (see log_events.csv).")
    return f"{len(inventory)} files, {len(events)} events"



class OdooDB:
    def __init__(self, run):
        self.run = run
        self.cr = None
        self.env = None
        self.odoo = self._import()
        self._init_config()
        self.dbname = self._resolve_db()
        from odoo import api, SUPERUSER_ID
        self.api, self.uid = api, SUPERUSER_ID
        try:
            from odoo.modules.registry import Registry
        except ImportError:
            Registry = self.odoo.registry
        self.registry = Registry(self.dbname)
        self.open()

    def _import(self):
        try:
            import odoo
            return odoo
        except ImportError:
            pass
        cands = [os.environ.get("ODOO_SRC"), self.run.home / "src" / "odoo", "/opt/odoo/odoo", "/opt/odoo",
                 "/usr/lib/python3/dist-packages", "/odoo"]
        for exe in ("odoo-bin", "odoo"):
            w = shutil.which(exe)
            if w:
                cands.append(Path(os.path.realpath(w)).parent)
        for c in cands:
            if c and (Path(c) / "odoo" / "__init__.py").is_file():
                sys.path.insert(0, str(c))
                import odoo
                return odoo
        raise RuntimeError("Odoo source not found; set ODOO_SRC to the folder containing the 'odoo' package")

    def _init_config(self):
        from odoo.tools import config
        argv = []
        conf = find_config(self.run)
        if conf:
            argv += ["-c", str(conf)]
        if self.run.args.db:
            argv += ["-d", self.run.args.db]
        argv += ["--logfile", str(self.run.out / "odoo_internal.log"), "--log-level", "warn"]
        config.parse_config(argv)
        self.config = config

    def _resolve_db(self):
        if self.run.args.db:
            return self.run.args.db
        name = self.config.get("db_name")
        if isinstance(name, (list, tuple)):
            name = name[0] if name else None
        if name:
            return str(name).split(",")[0].strip()
        if os.environ.get("PGDATABASE"):
            return os.environ["PGDATABASE"]
        from odoo.service import db as dbsvc
        dbs = dbsvc.list_dbs(force=True)
        if len(dbs) == 1:
            return dbs[0]
        raise RuntimeError(f"Cannot determine database; use --db (found: {dbs})")

    def open(self):
        self.close()
        self.cr = self.registry.cursor()
        self.cr.execute("SET TRANSACTION READ ONLY")
        self.cr.execute("SET LOCAL statement_timeout = %s", (int(self.run.timeout * 1000),))
        self.cr.execute("SET LOCAL lock_timeout = %s", (5000,))
        self.env = self.api.Environment(self.cr, self.uid, {"active_test": False, "lang": "en_US"})

    def close(self):
        if self.cr is not None:
            with contextlib.suppress(Exception):
                self.cr.rollback()
            with contextlib.suppress(Exception):
                self.cr.close()
        self.cr = None

    def alive(self):
        try:
            self.cr.execute("SELECT 1")
            return True
        except Exception:
            return False

    @contextlib.contextmanager
    def section(self, name):
        sp = "audit_" + re.sub(r"\W", "_", name)
        try:
            if not self.cr or self.cr.closed:
                self.open()
            self.cr.execute(f"SAVEPOINT {sp}")
            self.cr.execute("SET LOCAL statement_timeout = %s", (int(self.run.timeout * 1000),))
        except Exception:
            self.open()
            self.cr.execute(f"SAVEPOINT {sp}")
        try:
            yield self.env
            self.cr.execute(f"RELEASE SAVEPOINT {sp}")
        except Exception:
            try:
                self.cr.execute(f"ROLLBACK TO SAVEPOINT {sp}")
                with contextlib.suppress(Exception):
                    self.env.invalidate_all()
            except Exception:
                self.open()
            raise

    def sql(self, query, params=None):
        self.cr.execute(query, params or ())
        cols = [c[0] for c in self.cr.description]
        return [dict(zip(cols, r)) for r in self.cr.fetchall()]

    def has_table(self, table):
        return bool(self.sql("SELECT 1 FROM information_schema.tables WHERE table_name=%s", (table,)))

    def columns(self, table):
        return [r["column_name"] for r in self.sql(
            "SELECT column_name FROM information_schema.columns WHERE table_name=%s", (table,))]


def model(env, name):
    if name not in env.registry:
        raise Skip(f"{name} not installed")
    return env[name]


def pick(m, *names):
    return [n for n in names if n in m._fields]


def first(m, *names):
    for n in names:
        if n in m._fields:
            return n
    return None


def flat(rows):
    out = []
    for r in rows:
        d = {}
        for k, v in r.items():
            if isinstance(v, tuple) and len(v) == 2:
                v = v[1]
            elif isinstance(v, list):
                v = len(v)
            elif v is False:
                v = ""
            d[k] = v
        out.append(d)
    return out


def xmlid_map(db, model_name):
    rows = db.sql("SELECT res_id, module, name FROM ir_model_data WHERE model=%s", (model_name,))
    return {r["res_id"]: f"{r['module']}.{r['name']}" for r in rows}


def read(db, model_name, domain, fields, order="id", name=None):
    with db.section(name or model_name) as env:
        m = model(env, model_name)
        flds = pick(m, *fields)
        rows = m.search_read(domain, flds, limit=db.run.max_rows, order=order)
        if len(rows) >= db.run.max_rows:
            db.run.flag("Collector", f"{model_name}: row cap {db.run.max_rows} reached – export is partial.")
        return flat(rows)


def custom_modules(run):
    return set(run.facts.get("custom_modules", []))


def tag_origin(rows, xmap, custom):
    for r in rows:
        x = xmap.get(r.get("id"), "")
        mod = x.split(".")[0] if x else ""
        r["external_id"] = x
        r["origin"] = ("custom module" if mod in custom else "studio" if mod in ("studio_customization", "__custom__")
                       else "created in UI / data" if not mod or mod == "__export__" else "standard")
    return rows


def db_overview(run, db):
    import odoo
    with db.section("overview") as env:
        params = {p["key"]: p["value"] for p in env["ir.config_parameter"].sudo().search_read([], ["key", "value"])}
        pg = db.sql("SELECT version() AS v, pg_database_size(current_database()) AS size, current_user AS u")[0]
        role = db.sql("SELECT rolsuper FROM pg_roles WHERE rolname=current_user")
        companies = env["res.company"].search_count([])
        info = {
            "database": db.dbname,
            "odoo_version": odoo.release.version,
            "odoo_serie": getattr(odoo.release, "serie", ""),
            "database_create_date": params.get("database.create_date"),
            "database_uuid": params.get("database.uuid"),
            "subscription_expiration": params.get("database.expiration_date"),
            "subscription_expiration_reason": params.get("database.expiration_reason"),
            "web_base_url": params.get("web.base.url"),
            "postgres": pg["v"].split(",")[0],
            "database_size_mb": round(pg["size"] / 1e6, 1),
            "db_role": pg["u"],
            "db_role_superuser": bool(role and role[0]["rolsuper"]),
            "companies": companies,
        }
    run.facts["odoo"] = info
    run.write_json("odoo_overview", info)
    return f"Odoo {info['odoo_version']} db={db.dbname}"


def db_modules(run, db):
    from odoo.modules import module as modmod
    roots = std_roots(run)
    rows = read(db, "ir.module.module", [("state", "!=", "uninstalled")],
                ["name", "shortdesc", "author", "website", "license", "installed_version", "latest_version",
                 "state", "application", "create_date", "write_date"], order="name")
    custom = []
    for r in rows:
        try:
            path = modmod.get_module_path(r["name"], display_warning=False)
        except TypeError:
            path = modmod.get_module_path(r["name"])
        except Exception:
            path = None
        r["path"] = path or ""
        r["custom"] = bool(path and not is_std_path(path, roots)) or (not path and not STD_AUTHOR_RE.search(r.get("author") or ""))
        if r["custom"]:
            custom.append(r["name"])
    run.facts["custom_modules"] = custom
    run.write_csv("modules_installed", rows)
    cm = [r for r in rows if r["custom"]]
    run.write_csv("modules_custom", cm)
    pending = [r["name"] for r in rows if r["state"] in ("to upgrade", "to install", "to remove")]
    if pending:
        run.flag("Change management", f"Modules pending action (to install/upgrade/remove): {', '.join(pending)}.", "high")
    stale = [r["name"] for r in cm if r.get("latest_version") and r.get("installed_version")
             and r["latest_version"] != r["installed_version"]]
    if stale:
        run.flag("Change management", f"Custom modules whose deployed code version differs from the installed version (not upgraded): {', '.join(stale)}.")
    recent = [r["name"] for r in cm if str(r.get("write_date", ""))[:10] >= run.args.since.isoformat()]
    if recent:
        run.flag("Change management", f"Custom modules installed/updated since {run.args.since}: {', '.join(recent)}.")
    return f"{len(rows)} installed, {len(cm)} custom"


def db_users_and_groups(run, db):
    with db.section("users") as env:
        Users, Groups = env["res.users"], env["res.groups"]
        gfield = first(Groups, "users", "user_ids")
        gx = xmlid_map(db, "res.groups")
        name_f = first(Groups, "full_name", "display_name", "name")
        groups = Groups.search([])
        members, group_rows = defaultdict(set), []
        for g in groups:
            uids = g[gfield].ids if gfield else []
            for u in uids:
                members[u].add(g.id)
            cat = g.category_id.name if "category_id" in g._fields and g.category_id else ""
            group_rows.append({"id": g.id, "group": g[name_f], "external_id": gx.get(g.id, ""), "category": cat,
                               "members_total": len(uids), "share": g.share if "share" in g._fields else "",
                               "implied": "; ".join(g.implied_ids.mapped(name_f)) if "implied_ids" in g._fields else ""})
        gname = {r["id"]: r["group"] for r in group_rows}
        priv = {}
        for x, label in PRIVILEGED_GROUPS.items():
            rec = env.ref(x, raise_if_not_found=False)
            if rec:
                priv[rec.id] = label
        std_user_fields = set()
        custom = custom_modules(run)
        fx = db.sql("""SELECT f.name, d.module FROM ir_model_fields f JOIN ir_model_data d
                       ON d.model='ir.model.fields' AND d.res_id=f.id WHERE f.model='res.users'""")
        custom_bool = sorted({r["name"] for r in fx if r["module"] in custom
                              and Users._fields.get(r["name"]) is not None
                              and Users._fields[r["name"]].type == "boolean"})
        custom_bool += sorted(n for n, f in Users._fields.items() if n.startswith("x_") and f.type == "boolean")
        fields = pick(Users, "login", "name", "email", "active", "share", "company_id", "create_date", "create_uid",
                      "write_date", "write_uid", "login_date", "totp_enabled", "api_key_ids")
        last_login = {r["uid"]: r for r in db.sql(
            "SELECT create_uid AS uid, max(create_date) AS last, count(*) AS n FROM res_users_log GROUP BY create_uid")} \
            if db.has_table("res_users_log") else {}
        users = Users.search([], order="id")
        rows, matrix = [], []
        for u in users:
            r = {"id": u.id}
            for f in fields:
                v = u[f]
                if hasattr(v, "_name"):
                    v = v.display_name if len(v) == 1 else len(v)
                r[f] = v
            r["companies"] = "; ".join(u.company_ids.mapped("name")) if "company_ids" in u._fields else ""
            r["last_login_log"] = last_login.get(u.id, {}).get("last")
            r["login_log_entries"] = last_login.get(u.id, {}).get("n", 0)
            ug = members.get(u.id, set())
            r["user_type"] = "internal" if not u.share else "portal/public"
            r["privileged_roles"] = "; ".join(sorted(priv[g] for g in ug if g in priv))
            r["groups"] = "; ".join(sorted(gname.get(g, str(g)) for g in ug))
            for cf in custom_bool:
                r[f"custom:{cf}"] = u[cf]
            rows.append(r)
            if r["privileged_roles"]:
                mrow = {"login": u.login, "name": u.name, "active": u.active}
                mrow.update({label: ("Y" if gid in ug else "") for gid, label in priv.items()})
                matrix.append(mrow)
    run.write_csv("users", rows)
    run.write_csv("groups", group_rows)
    run.write_csv("privileged_access_matrix", matrix)
    assess_users(run, rows, custom_bool)
    return f"{len(rows)} users, {len(group_rows)} groups"


def assess_users(run, rows, custom_bool):
    internal = [r for r in rows if r["user_type"] == "internal" and r.get("active") and r["id"] != 1]
    run.facts["users"] = {"active_internal": len(internal), "total": len(rows)}
    domains = Counter((r.get("email") or r.get("login") or "").split("@")[-1].lower()
                      for r in internal if "@" in (r.get("email") or r.get("login") or ""))
    main_domain = domains.most_common(1)[0][0] if domains else None
    admins = [r for r in internal if "Settings (Administrator)" in r["privileged_roles"]]
    run.facts["users"]["administrators"] = [r["login"] for r in admins]
    if admins:
        run.flag("Access", f"{len(admins)} active user(s) with Settings/Administrator rights: {', '.join(r['login'] for r in admins)}.")
    if "totp_enabled" in (rows[0] if rows else {}):
        no2fa = [r["login"] for r in admins if not r.get("totp_enabled")]
        if no2fa:
            run.flag("Access", f"Administrators without two-factor authentication: {', '.join(no2fa)}.", "high")
        all_no2fa = sum(1 for r in internal if not r.get("totp_enabled"))
        run.facts["users"]["internal_without_2fa"] = all_no2fa
    if main_domain:
        ext = [r["login"] for r in admins if main_domain not in (r.get("email") or r.get("login") or "").lower()]
        if ext:
            run.flag("Access", f"Administrators outside the main email domain ({main_domain}) – likely vendor/partner accounts: {', '.join(ext)}.")
    generic = [r["login"] for r in internal if GENERIC_LOGIN_RE.search(r.get("login") or "")]
    if generic:
        run.flag("Access", f"Possible generic/shared or test accounts active: {', '.join(generic)}.")
    cutoff = (dt.datetime.now() - dt.timedelta(days=90)).isoformat()
    dormant = [r["login"] for r in internal if r.get("last_login_log") and str(r["last_login_log"]) < cutoff]
    never = [r["login"] for r in internal if not r.get("last_login_log") and not r.get("login_date")]
    if dormant:
        run.flag("Access", f"Active internal users with no login in 90 days: {', '.join(dormant)}.")
    if never:
        run.flag("Access", f"Active internal users with no recorded login: {', '.join(never)}.")
    for cf in custom_bool:
        on = [r["login"] for r in internal if r.get(f"custom:{cf}")]
        if on:
            run.flag("Customisations", f"Custom user right '{cf}' enabled for {len(on)} user(s): {', '.join(on) or 'none'}.")
    new = [r["login"] for r in rows if str(r.get("create_date", ""))[:10] >= run.args.since.isoformat()]
    run.facts["users"]["created_since"] = len(new)


def db_api_keys(run, db):
    with db.section("apikeys"):
        if not db.has_table("res_users_apikeys"):
            raise Skip("API keys table not present")
        cols = [c for c in ("id", "name", "user_id", "scope", "create_date", "expiration_date") if c in db.columns("res_users_apikeys")]
        rows = db.sql(f"""SELECT {', '.join('k.' + c for c in cols)}, u.login FROM res_users_apikeys k
                          LEFT JOIN res_users u ON u.id = k.user_id ORDER BY k.id""")
    run.write_csv("api_keys", rows)
    if rows:
        run.flag("Access", f"{len(rows)} API key(s) exist for: {', '.join(sorted({str(r['login']) for r in rows}))} (key values not extracted).")
    return f"{len(rows)} keys"


def db_login_history(run, db):
    with db.section("login_history"):
        if not db.has_table("res_users_log"):
            raise Skip("res_users_log not present")
        rows = db.sql("""SELECT l.create_date AS login_time, u.login, l.create_uid AS user_id FROM res_users_log l
                         LEFT JOIN res_users u ON u.id = l.create_uid WHERE l.create_date >= %s
                         ORDER BY l.create_date DESC LIMIT %s""", (run.args.since, run.max_rows))
    run.write_csv("login_history_db", rows)
    return f"{len(rows)} rows (Odoo keeps only recent entries per user)"


def db_config_parameters(run, db):
    rows = read(db, "ir.config_parameter", [], ["key", "value", "create_date", "create_uid", "write_date", "write_uid"], order="key")
    for r in rows:
        r["value"] = redact_value(r["key"], r["value"])
    run.write_csv("system_parameters", rows)
    keys = {r["key"]: r["value"] for r in rows}
    minlen = keys.get("auth_password_policy.minlength")
    if not minlen or str(minlen).isdigit() and int(minlen) < 8:
        run.flag("Access", f"Password minimum length is {minlen or 'not set (Odoo default)'}.")
    changed = [r["key"] for r in rows if r.get("write_date") and r.get("create_date")
               and str(r["write_date"])[:10] >= run.args.since.isoformat()
               and (r["write_date"] - r["create_date"]).total_seconds() > 60
               and not r["key"].startswith(("database.", "web.base.url"))]
    if changed:
        run.flag("Configuration", f"System parameters changed since {run.args.since}: {', '.join(changed[:30])}.")
    return f"{len(rows)} parameters"


def db_companies(run, db):
    rows = read(db, "res.company", [], ["name", "currency_id", "country_id", "parent_id", "fiscalyear_last_month",
                                        "fiscalyear_last_day", "fiscalyear_lock_date", "period_lock_date", "tax_lock_date",
                                        "hard_lock_date", "sale_lock_date", "purchase_lock_date",
                                        "check_account_audit_trail", "restrictive_audit_trail", "anglo_saxon_accounting",
                                        "account_storno", "create_date", "write_date"], order="id")
    run.write_csv("companies_and_lock_dates", rows)
    for r in rows:
        locks = {k: r.get(k) for k in ("fiscalyear_lock_date", "period_lock_date", "tax_lock_date", "hard_lock_date") if k in r}
        if locks and not any(locks.values()):
            run.flag("Accounting controls", f"No accounting lock dates set for {r['name']}.")
        for k in ("check_account_audit_trail", "restrictive_audit_trail"):
            if k in r and not r[k]:
                run.flag("Accounting controls", f"Accounting audit trail setting ({k}) is off for {r['name']}.")
    return f"{len(rows)} companies"


def db_journals(run, db):
    rows = read(db, "account.journal", [], ["name", "code", "type", "company_id", "active", "restrict_mode_hash_table",
                                            "create_date", "write_date"], order="company_id,code")
    run.write_csv("journals", rows)
    if rows and "restrict_mode_hash_table" in rows[0]:
        off = [f"{r['company_id']}/{r['code']}" for r in rows if r["type"] in ("sale", "purchase") and r.get("active")
               and not r["restrict_mode_hash_table"]]
        if off:
            run.flag("Accounting controls", f"Sales/purchase journals without hash lock (posted entries can be reset to draft): {', '.join(off)}.")
    return f"{len(rows)} journals"


def db_custom_fields(run, db):
    custom = custom_modules(run)
    with db.section("custom_fields") as env:
        rows = db.sql("""SELECT f.id, f.model, f.name, f.field_description AS label, f.ttype, f.state, f.relation,
                                f.store, f.create_date, f.write_date, d.module
                         FROM ir_model_fields f
                         LEFT JOIN ir_model_data d ON d.model='ir.model.fields' AND d.res_id=f.id
                         WHERE f.state='manual' OR d.module = ANY(%s) ORDER BY f.model, f.name""", (list(custom),))
        for r in rows:
            if isinstance(r["label"], dict):
                r["label"] = r["label"].get("en_US") or next(iter(r["label"].values()), "")
            r["origin"] = "studio/manual" if r["state"] == "manual" else f"custom module {r['module']}"
    run.write_csv("custom_fields", rows)
    return f"{len(rows)} fields"


def db_views(run, db):
    custom = custom_modules(run)
    rows = read(db, "ir.ui.view", [], ["name", "model", "type", "inherit_id", "mode", "active", "priority",
                                       "create_date", "create_uid", "write_date", "write_uid"], name="views")
    xmap = xmlid_map(db, "ir.ui.view")
    tag_origin(rows, xmap, custom)
    rows = [r for r in rows if r["origin"] != "standard"]
    run.write_csv("views_custom_or_ui", rows)
    return f"{len(rows)} non-standard views"


def db_server_actions(run, db):
    custom = custom_modules(run)
    rows = read(db, "ir.actions.server", [], ["name", "model_name", "model_id", "state", "usage", "binding_model_id",
                                              "code", "create_date", "create_uid", "write_date", "write_uid"],
                name="server_actions")
    tag_origin(rows, xmlid_map(db, "ir.actions.server"), custom)
    rows = [r for r in rows if r["origin"] != "standard" or r.get("usage") == "base_automation"]
    run.write_csv("server_actions_custom_or_ui", rows)
    for r in rows:
        if r.get("state") == "code" and r.get("code"):
            safe = re.sub(r"[^\w\-]+", "_", f"{r['id']}_{r['name']}")[:80]
            run.write_text(f"server_action_code/{safe}.py", f"# {r['name']} | model {r.get('model_name')} | {r['origin']}\n{r['code']}")
    code_recent = [r["name"] for r in rows if r.get("state") == "code"
                   and str(r.get("write_date", ""))[:10] >= run.args.since.isoformat()]
    if code_recent:
        run.flag("Change management", f"Python server actions created/changed since {run.args.since}: {', '.join(code_recent[:20])}.")
    return f"{len(rows)} actions"


def db_automations(run, db):
    custom = custom_modules(run)
    rows = read(db, "base.automation", [], ["name", "model_id", "trigger", "active", "filter_domain",
                                            "filter_pre_domain", "trigger_field_ids", "action_server_ids",
                                            "action_server_id", "create_date", "create_uid", "write_date", "write_uid"],
                name="automations")
    tag_origin(rows, xmlid_map(db, "base.automation"), custom)
    run.write_csv("automation_rules", rows)
    ui = [r["name"] for r in rows if r["origin"] in ("studio", "created in UI / data") and r.get("active")]
    if ui:
        run.flag("Change management", f"Active automation rules created in the UI/Studio (outside code deployment): {', '.join(ui[:20])}.")
    return f"{len(rows)} rules"


def db_crons(run, db):
    rows = read(db, "ir.cron", [], ["cron_name", "name", "model_id", "active", "interval_number", "interval_type",
                                    "nextcall", "lastcall", "numbercall", "priority", "user_id", "state", "code",
                                    "create_date", "write_date", "write_uid"], name="crons")
    tag_origin(rows, xmlid_map(db, "ir.cron"), custom_modules(run))
    run.write_csv("scheduled_actions", rows)
    return f"{len(rows)} crons"


def db_access_rules(run, db):
    custom = custom_modules(run)
    acl = read(db, "ir.model.access", [], ["name", "model_id", "group_id", "perm_read", "perm_write", "perm_create",
                                           "perm_unlink", "active"], name="acl")
    tag_origin(acl, xmlid_map(db, "ir.model.access"), custom)
    rules = read(db, "ir.rule", [], ["name", "model_id", "groups", "domain_force", "perm_read", "perm_write",
                                     "perm_create", "perm_unlink", "global", "active", "write_date"], name="rules")
    tag_origin(rules, xmlid_map(db, "ir.rule"), custom)
    run.write_csv("access_control_lists", acl)
    run.write_csv("record_rules", rules)
    nonstd = sum(1 for r in acl + rules if r["origin"] != "standard")
    return f"{len(acl)} ACLs, {len(rules)} rules, {nonstd} non-standard"


def db_mail_and_auth(run, db):
    done = []
    for name, model_name, fields in (
            ("mail_servers", "ir.mail_server", ["name", "smtp_host", "smtp_port", "smtp_user", "smtp_encryption",
                                                "smtp_authentication", "from_filter", "active", "write_date"]),
            ("incoming_mail_servers", "fetchmail.server", ["name", "server", "port", "user", "server_type", "is_ssl",
                                                           "state", "active", "write_date"]),
            ("oauth_providers", "auth.oauth.provider", ["name", "auth_endpoint", "client_id", "enabled", "write_date"]),
            ("ldap_servers", "res.company.ldap", ["ldap_server", "ldap_server_port", "ldap_base", "ldap_tls",
                                                  "create_user", "company", "write_date"])):
        try:
            rows = read(db, model_name, [], fields, name=name)
            run.write_csv(name, rows)
            done.append(f"{name}={len(rows)}")
        except Skip:
            continue
    return ", ".join(done) or "none"


def db_ir_logging(run, db):
    rows = read(db, "ir.logging", [("create_date", ">=", run.args.since.isoformat())],
                ["create_date", "name", "type", "level", "dbname", "path", "func", "line", "message"],
                order="create_date desc", name="ir_logging")
    for r in rows:
        r["message"] = (r.get("message") or "")[:1000]
    run.write_csv("ir_logging_since", rows)
    return f"{len(rows)} entries"


def db_studio_and_tracking(run, db):
    out = {}
    with db.section("studio"):
        out["studio_installed"] = bool(db.sql("SELECT 1 FROM ir_module_module WHERE name='web_studio' AND state='installed'"))
        out["studio_records"] = db.sql("""SELECT model, count(*) AS n FROM ir_model_data
                                          WHERE module='studio_customization' GROUP BY model ORDER BY n DESC""")
    with db.section("tracking"):
        if db.has_table("mail_tracking_value") and "field_id" in db.columns("mail_tracking_value"):
            out["tracked_changes_since_by_model"] = db.sql(
                """SELECT m.model, count(*) AS changes FROM mail_tracking_value t
                   JOIN mail_message m ON m.id = t.mail_message_id
                   WHERE t.create_date >= %s GROUP BY m.model ORDER BY changes DESC LIMIT 50""", (run.args.since,))
    run.write_json("studio_and_tracking", out)
    if out.get("studio_records"):
        run.flag("Change management", "Odoo Studio customisations exist (studio_customization module) – these are changed in LIVE without a code deployment.")
    return f"studio={out['studio_installed']}"


DB_STEPS = [
    ("db_overview", db_overview), ("db_modules", db_modules), ("db_users_groups", db_users_and_groups),
    ("db_api_keys", db_api_keys), ("db_login_history", db_login_history), ("db_parameters", db_config_parameters),
    ("db_companies", db_companies), ("db_journals", db_journals), ("db_custom_fields", db_custom_fields),
    ("db_views", db_views), ("db_server_actions", db_server_actions), ("db_automations", db_automations),
    ("db_crons", db_crons), ("db_access_rules", db_access_rules), ("db_mail_auth", db_mail_and_auth),
    ("db_ir_logging", db_ir_logging), ("db_studio_tracking", db_studio_and_tracking),
]



def write_summary(run):
    f = run.facts
    o = f.get("odoo", {})
    lines = [
        "# Odoo.sh evidence collection – summary",
        "",
        f"Collector v{VERSION} · Author: Nimrod Moyo, BSc, MSc, CISSP, CEH, CC",
        f"Run: {run.started:%Y-%m-%d %H:%M:%S} → {dt.datetime.now():%H:%M:%S} on `{f.get('hostname')}` as `{f.get('run_by_os_user')}`",
        f"Period reviewed from: {run.args.since}",
        "",
        "## Environment",
        f"- Odoo {o.get('odoo_version', 'n/a')} · database `{o.get('database', 'n/a')}` (created {o.get('database_create_date', 'n/a')})",
        f"- Subscription expiry: {o.get('subscription_expiration', 'n/a')} · PostgreSQL: {o.get('postgres', 'n/a')} · size {o.get('database_size_mb', 'n/a')} MB",
        f"- Odoo.sh layout detected: {f.get('odoo_sh_layout')} · config: `{f.get('config_path', 'n/a')}`",
        f"- Custom modules: {', '.join(f.get('custom_modules', [])) or 'none found'}",
        f"- Users: {f.get('users', {})}",
        f"- Git: {f.get('git', {})}",
        f"- Logs: {f.get('logs', {})}",
        "",
        "## Points to note",
    ]
    order = {"high": 0, "note": 1}
    for fl in sorted(run.flags, key=lambda x: (order.get(x["severity"], 2), x["area"])):
        lines.append(f"- **{fl['area']}**{' (high)' if fl['severity'] == 'high' else ''}: {fl['observation']}")
    if not run.flags:
        lines.append("- None generated.")
    lines += ["", "## Collection status", "", "| Step | Status | Attempts | Seconds | Detail |", "|---|---|---|---|---|"]
    for s in run.status:
        lines.append(f"| {s['step']} | {s['status']} | {s['attempts']} | {s['seconds']} | {str(s['detail'])[:120].replace('|', '/')} |")
    lines += ["", "Observations are automated indicators for follow-up, not audit conclusions."]
    run.write_text("SUMMARY.md", "\n".join(lines))
    run.write_csv("observations", run.flags, ["area", "severity", "observation"])
    run.write_csv("collection_status", run.status, ["step", "status", "attempts", "seconds", "detail"])


def finalise(run):
    manifest = []
    for p in sorted(run.out.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.json":
            manifest.append({"file": str(p.relative_to(run.out)), "bytes": p.stat().st_size, "sha256": sha256(p)})
    (run.out / "MANIFEST.json").write_text(json.dumps({"generated": dt.datetime.now().isoformat(),
                                                      "files": manifest}, indent=2), encoding="utf-8")
    if run.args.no_zip:
        return run.out
    zpath = run.out.with_suffix(".zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(run.out.rglob("*")):
            if p.is_file():
                z.write(p, Path(run.out.name) / p.relative_to(run.out))
    (zpath.parent / (zpath.name + ".sha256")).write_text(f"{sha256(zpath)}  {zpath.name}\n")
    return zpath


@contextlib.contextmanager
def single_instance(run):
    lock = run.out.parent / ".collector.lock"
    if lock.exists():
        try:
            pid = int(lock.read_text().strip())
            os.kill(pid, 0)
            raise SystemExit(f"Another collector run is active (pid {pid}).")
        except (ValueError, ProcessLookupError, PermissionError):
            lock.unlink(missing_ok=True)
    lock.write_text(str(os.getpid()))
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def parse_args():
    ap = argparse.ArgumentParser(description="Read-only Odoo.sh IT audit evidence collector (Nimrod Moyo, BSc, MSc, CISSP, CEH, CC)")
    ap.add_argument("--db")
    ap.add_argument("--config")
    ap.add_argument("--out")
    ap.add_argument("--since", type=lambda s: dt.date.fromisoformat(s), default=dt.date(dt.date.today().year, 1, 1))
    ap.add_argument("--skip", type=lambda s: {x.strip() for x in s.split(",") if x.strip()}, default=set())
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=60, help="SQL statement timeout in seconds")
    ap.add_argument("--max-rows", type=int, default=100000)
    ap.add_argument("--log-mb", type=float, default=50)
    ap.add_argument("--max-minutes", type=float, default=30)
    ap.add_argument("--ticket-pattern", default=DEFAULT_TICKET_PATTERN,
                    help="regex for SOW/ticket references in commit messages")
    ap.add_argument("--no-zip", action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
    args.retries = max(1, args.retries)
    run = Run(args)
    with contextlib.suppress(Exception):
        os.nice(10)
    with single_instance(run):
        run.log.info("Odoo.sh IT audit evidence collector v%s – output: %s", VERSION, run.out)
        for name, fn in (("environment", collect_environment), ("odoo_config", collect_config)):
            step(run, name, fn)
        db = None
        if "db" not in args.skip and any(name not in args.skip for name, _ in DB_STEPS):
            for attempt in range(1, args.retries + 1):
                try:
                    db = OdooDB(run)
                    run.log.info("connected to database %s (read-only transaction)", db.dbname)
                    break
                except Exception as e:
                    run.log.warning("database connection attempt %d failed: %s", attempt, e)
                    if attempt == args.retries or not is_transient(e):
                        run.status.append({"step": "db_connect", "status": "failed", "attempts": attempt,
                                           "seconds": 0, "detail": f"{type(e).__name__}: {e}"})
                        with open(run.out / "errors.log", "a", encoding="utf-8") as fh:
                            fh.write(traceback.format_exc())
                        break
                    time.sleep(2 ** attempt)
        if db:
            try:
                for name, fn in DB_STEPS:
                    if name != "db_overview" and not db.alive():
                        run.log.warning("database cursor lost – reconnecting")
                        db.open()
                    step(run, name, fn, db)
            finally:
                db.close()
        for name, fn in (("git", collect_git), ("custom_code_hashes", collect_code_hashes), ("logs", collect_logs)):
            step(run, name, fn)
        write_summary(run)
        result = finalise(run)
    failed = [s["step"] for s in run.status if s["status"] == "failed"]
    run.log.info("finished – %d steps, %d failed%s", len(run.status), len(failed), f" ({', '.join(failed)})" if failed else "")
    run.log.info("evidence package: %s", result)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
