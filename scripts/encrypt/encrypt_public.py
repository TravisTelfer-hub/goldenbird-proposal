#!/usr/bin/env python3
"""
Encrypt every HTML file in public-encrypted/ with StatiCrypt and write the protected
copies to public/ (the folder GitHub Pages serves). Plaintext source is local-only:
public-encrypted/ is gitignored and never tracked.

Password strategy: derived passwords (default)
  Each file's password = HMAC-SHA256(ENCRYPT_SECRET, relative_path), base64, 24 chars.
  One master secret in your password manager, a different password per page, any
  password regenerable from secret + path. The secret never touches the repo.
  ENCRYPT_PASSWORD=<value> in .env switches EVERY file to that single password (one
  password per person is the Webprofits rule for personal repos; a client portal keeps
  its own). Remove the line to go back to derived passwords.

Usage:
    python3 scripts/encrypt/encrypt_public.py                  # encrypt all -> public/, validate the release
    python3 scripts/encrypt/encrypt_public.py --skip-unchanged # skip pages whose fingerprint is current
    python3 scripts/encrypt/encrypt_public.py --file reports/q1.html
    python3 scripts/encrypt/encrypt_public.py --show           # counts + where the secret lives, no values
    python3 scripts/encrypt/encrypt_public.py --show --reveal  # the password table, terminal only, never in CI

What a run never does: print a password (the table needs --reveal on a TTY), treat a page
as "already encrypted" because it mentions the tool (the page must be the exact render of an
approved template with approved label values - the same check CI runs), use a template whose
digest is not in release-manifest.json, write a label value outside an approved profile (it
passes no --template-* flags, so every page carries the library defaults = profile "default"),
skip a page on timestamps alone (the fingerprint covers source, password, template, salt config
and the StatiCrypt version), or publish a release that fails release-manifest.json.

Requirements: Node.js (npx). StatiCrypt is pinned to STATICRYPT_VERSION below.
"""

import argparse
import base64
import fnmatch
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ---- CONFIG (the only block that differs between the shared template and its scaffold copies) ----
WORKSPACE_FROM = "file"          # "file": repo root is 2 levels above this script; "cwd": run from the repo root
OUTPUT_SUBDIR = "public"         # the folder Pages serves
DEFAULT_MODE = "derived"         # "derived": per-file HMAC unless ENCRYPT_PASSWORD is set; "shared": ENCRYPT_PASSWORD required
ALLOW_DERIVED = True             # "shared" repos may still opt a page into a derived password with --derived
SYNC_ASSETS = False              # mirror non-HTML, non-data assets from the source dir into the release
EXTRA_ASSETS = []                # [("portal", ["portal.css", "portal.js"])]: repo-root dirs whose listed files ship
# ---- END CONFIG ----

STATICRYPT_VERSION = "3.5.4"
STATICRYPT_PKG = f"staticrypt@{STATICRYPT_VERSION}"
WORKSPACE = Path.cwd() if WORKSPACE_FROM == "cwd" else Path(__file__).resolve().parent.parent.parent

# Load .env from the workspace root if present (stdlib only; a real env var wins).
_env_file = WORKSPACE / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

SOURCE_DIR = WORKSPACE / "public-encrypted"
OUTPUT_DIR = WORKSPACE / OUTPUT_SUBDIR
TEMPLATE = Path(__file__).resolve().parent / "template.html"
CONFIG_FILE = WORKSPACE / ".staticrypt.json"          # holds the salt every page was encrypted with
FINGERPRINT_FILE = Path(__file__).resolve().parent / "encrypt-manifest.json"
RELEASE_MANIFEST = WORKSPACE / "release-manifest.json"

# ---- release-guard shared block start (lifted verbatim into the encryptors; edit here, then sync) ----
STATICRYPT_VERSION = "3.5.4"
HELPER_NAME = "render-check.cjs"
ENVELOPE_RE = re.compile(r"staticryptConfig\s*=\s*(\{.*?\})\s*(?:;|\n|</script>)", re.S)
DEFAULT_TEMPLATE_PATHS = ["scripts/encrypt/template.html"]

HTML_EXT = {".html", ".htm"}
DATA_EXT = {".json", ".csv", ".tsv", ".xlsx", ".xls", ".md", ".txt", ".yml", ".yaml", ".sql", ".xml", ".ndjson"}
ASSET_EXT = {".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot"}
PAGES_CONTROL_FILES = {".nojekyll", "CNAME"}
NEVER_NAMES = ["CLAUDE.md", ".env*", "settings.local.json", "*.lock.json", "passwords*", "*-raw.json",
               "Makefile", "lefthook.yml", ".gitignore", ".staticrypt.json", "release-manifest.json",
               "encrypt-manifest.json", ".DS_Store"]
NEVER_DIRS = ["scripts", "public-encrypted", "private", ".git", ".github", ".claude", "node_modules", "_internal"]
MANIFEST_KEYS = {"release_root", "public_plain", "public_data", "public_files", "bundles", "passthrough", "never",
                 "approved_templates", "template_paths", "label_profiles"}
LABEL_FIELDS = ("template_title", "template_instructions", "template_button", "template_placeholder", "template_remember",
                "template_error", "template_toggle_show", "template_toggle_hide", "template_color_primary", "template_color_secondary")
BUILTIN_PROFILES = ("default",)   # the library's own CLI defaults, defined in render-check.cjs; a manifest cannot redefine it
LIST_KEYS = ("public_plain", "public_data", "public_files", "bundles", "passthrough", "never", "approved_templates", "template_paths")


def _no_duplicate_keys(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate key '{k}'")
        seen.add(k)
    return dict(pairs)


def find_helper(*extra_dirs) -> Path:
    """The node helper that performs the exact render check. Fail closed when it is missing."""
    env = os.environ.get("RELEASE_GUARD_HELPER")
    candidates = ([Path(env)] if env else []) + [Path(d) / HELPER_NAME for d in extra_dirs] + [Path(__file__).resolve().parent / HELPER_NAME]
    for c in candidates:
        if c.is_file():
            return c
    raise SystemExit(f"RELEASE BLOCKED: {HELPER_NAME} not found next to the guard (looked in {[str(c) for c in candidates]}) - the exact StatiCrypt check cannot run")


def exact_envelope_check(files, templates, helper: Path = None, profiles: dict = None) -> dict:
    """Run render-check.cjs on `files` with the approved `templates` (the library default is always included)
    and the manifest's label `profiles` (the built-in `default` is always included).
    Returns {str(path): (ok: bool, reason: str, template_sha256: str)}. Fails closed when the pinned library
    is absent or the helper misbehaves."""
    files = [str(Path(f)) for f in files]
    out = {}
    if not files:
        return out
    helper = helper or find_helper()
    for i in range(0, len(files), 400):
        chunk = files[i:i + 400]
        payload = json.dumps({"files": chunk, "templates": [str(t) for t in templates], "profiles": profiles or {}})
        try:
            r = subprocess.run(["node", str(helper)], input=payload, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            raise SystemExit("RELEASE BLOCKED: node is not installed - the exact StatiCrypt check cannot run")
        except subprocess.TimeoutExpired:
            raise SystemExit("RELEASE BLOCKED: the exact StatiCrypt check timed out")
        try:
            data = json.loads(r.stdout or "{}")
        except ValueError:
            raise SystemExit(f"RELEASE BLOCKED: {HELPER_NAME} returned no verdict (exit {r.returncode})")
        if r.returncode == 2 or "error" in data:
            raise SystemExit("RELEASE BLOCKED: " + data.get("error", f"{HELPER_NAME} exited {r.returncode}"))
        if r.returncode != 0 or "results" not in data:
            raise SystemExit(f"RELEASE BLOCKED: {HELPER_NAME} exited {r.returncode} without results")
        for res in data["results"]:
            out[res["file"]] = (bool(res.get("ok")), res.get("reason", ""), res.get("template_sha256", ""))
    missing = [f for f in files if f not in out]
    if missing:
        raise SystemExit(f"RELEASE BLOCKED: {HELPER_NAME} returned no verdict for {len(missing)} file(s)")
    return out


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def template_path_problem(rel: str, base: Path) -> str:
    """Why a `template_paths` entry is unsafe, or "" when it is a regular file inside the repo reached through
    no symlink at any ancestor or final component. Checked before the file is read."""
    if rel.startswith("/") or ".." in rel.split("/") or not rel.strip():
        return "must be a relative path inside the repo"
    base_real = base.resolve()
    cur = base
    for part in Path(rel).parts:
        cur = cur / part
        if cur.is_symlink():
            return f"'{cur.relative_to(base).as_posix()}' is a symlink (templates and their ancestors must be real paths)"
    if not cur.exists():
        return "does not exist (remove the entry or add the file)"
    if not cur.is_file():
        return "is not a regular file"
    try:
        cur.resolve().relative_to(base_real)
    except ValueError:
        return "resolves outside the repo"
    return ""


def candidate_templates(manifest: dict, base: Path) -> list:
    """Every template file the manifest names in `template_paths`, relative to `base`, with its sha256 and whether
    the manifest approves it. An unsafe entry (missing, symlinked at any component, outside the repo) BLOCKS the
    release outright - also when the library default would otherwise satisfy every page."""
    out = []
    for rel in manifest.get("template_paths") or []:
        problem = template_path_problem(rel, base)
        if problem:
            raise SystemExit(f"RELEASE BLOCKED: template_paths entry '{rel}' {problem}")
        p = base / rel
        sha = sha256_file(p)
        out.append((p, sha, sha in manifest.get("approved_templates", [])))
    return out


def approved_template_files(manifest: dict, base: Path) -> list:
    """The ONE approval set: manifest-listed template files whose digest is in approved_templates (the library
    default is added by the helper). Standalone validation, passthrough, already-encrypted detection, skipping
    and the encryptor's final validation all use exactly this list."""
    return [p for p, _, ok in candidate_templates(manifest, base) if ok]


def is_staticrypt_output(path: Path, templates=(), helper: Path = None, profiles: dict = None) -> bool:
    """Single-file convenience; callers with many files use exact_envelope_check once."""
    return exact_envelope_check([path], list(templates), helper, profiles)[str(Path(path))][0]


def match(rel: str, pattern: str) -> bool:
    pattern = pattern.strip()
    if pattern.endswith("/"):
        return rel == pattern[:-1] or rel.startswith(pattern)
    return fnmatch.fnmatchcase(rel, pattern)


def matches_any(rel: str, patterns) -> bool:
    return any(match(rel, p) for p in (patterns or []))


def forbidden_reason(rel: str, extra_never) -> str:
    parts = rel.split("/")
    name = parts[-1]
    for pat in NEVER_NAMES:
        if fnmatch.fnmatchcase(name, pat):
            return f"forbidden file name ({pat})"
    for d in parts[:-1]:
        if d in NEVER_DIRS:
            return f"forbidden directory ({d}/) at any depth"
    for pat in extra_never or []:
        if match(rel, pat) or any(fnmatch.fnmatchcase(part, pat.rstrip("/")) for part in parts):
            return f"forbidden by manifest never ({pat})"
    return ""


def classify(p: Path) -> str:
    ext = p.suffix.lower()
    if p.name in PAGES_CONTROL_FILES:
        return "asset"
    if ext in HTML_EXT:
        return "html"
    if ext in DATA_EXT:
        return "data"
    if ext in (".js", ".mjs"):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
            if text.lstrip()[:1] in ("{", "["):
                json.loads(text)
                return "data"
        except (ValueError, OSError):
            pass
        return "review"
    if ext in ASSET_EXT:
        return "asset"
    return "review"


def load_manifest(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"RELEASE BLOCKED: no release manifest at {path} - every release needs a reviewed allowlist")
    try:
        m = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except ValueError as e:
        raise SystemExit(f"RELEASE BLOCKED: {path} is not valid JSON ({e})")
    if not isinstance(m, dict):
        raise SystemExit(f"RELEASE BLOCKED: {path} must be a JSON object")
    unknown = set(m) - MANIFEST_KEYS
    if unknown:
        raise SystemExit(f"RELEASE BLOCKED: {path} has unknown key(s) {sorted(unknown)} - a typo here would silently allow nothing or everything")
    if not isinstance(m.get("release_root"), str) or not m["release_root"].strip():
        raise SystemExit(f"RELEASE BLOCKED: {path} must name release_root (the directory Pages serves)")
    for key in LIST_KEYS:
        v = m.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            raise SystemExit(f"RELEASE BLOCKED: manifest key '{key}' must be a list of non-empty strings")
        m[key] = v
    for h in m["approved_templates"]:
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            raise SystemExit("RELEASE BLOCKED: approved_templates entries must be sha256 hex digests")
    for rel in m["template_paths"]:
        if rel.startswith("/") or ".." in rel.split("/"):
            raise SystemExit("RELEASE BLOCKED: template_paths entries must be relative paths inside the repo")
    profiles = m.get("label_profiles", {})
    if not isinstance(profiles, dict):
        raise SystemExit("RELEASE BLOCKED: manifest key 'label_profiles' must be an object of {name: {field: value}}")
    for name, prof in profiles.items():
        if not isinstance(name, str) or not name.strip():
            raise SystemExit("RELEASE BLOCKED: label_profiles names must be non-empty strings")
        if name in BUILTIN_PROFILES:
            raise SystemExit(f"RELEASE BLOCKED: label profile '{name}' is built in (the library defaults) and cannot be redefined")
        if not isinstance(prof, dict) or not prof:
            raise SystemExit(f"RELEASE BLOCKED: label profile '{name}' must be a non-empty object of field: value")
        bad = set(prof) - set(LABEL_FIELDS)
        if bad:
            raise SystemExit(f"RELEASE BLOCKED: label profile '{name}' has unknown field(s) {sorted(bad)}; allowed: {list(LABEL_FIELDS)}")
        if not all(isinstance(v, str) for v in prof.values()):
            raise SystemExit(f"RELEASE BLOCKED: label profile '{name}' values must be strings")
    m["label_profiles"] = profiles
    return m

def check_release(root: Path, manifest: dict, templates=(), helper: Path = None):
    """Return (violations, counts). violations = list of (rel_path, reason). Paths only, never contents."""
    violations = []
    counts = {"files": 0, "encrypted_html": 0, "plain_html_allowed": 0, "data_allowed": 0, "files_allowed": 0, "assets": 0}
    bundles = manifest.get("bundles") or []
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            full = Path(dirpath) / d
            if full.is_symlink():
                violations.append(((full.relative_to(root)).as_posix() + "/", "symlinked directory (not allowed in a release)"))
                dirnames.remove(d)
        for f in filenames:
            p = Path(dirpath) / f
            rel = p.relative_to(root).as_posix()
            counts["files"] += 1
            if p.is_symlink():
                violations.append((rel, "symlink (not allowed in a release)"))
                continue
            reason = forbidden_reason(rel, manifest.get("never"))
            if reason:
                violations.append((rel, reason))
                continue
            entries.append((p, rel))
    html_paths = [p for p, _ in entries if classify(p) == "html"]
    verdicts = exact_envelope_check(html_paths, list(templates), helper, manifest.get("label_profiles")) if html_paths else {}
    for p, rel in entries:
        in_bundle = any(match(rel, b) for b in bundles)
        kind = classify(p)
        if kind == "html":
            ok, why, _ = verdicts[str(p)]
            if ok:
                counts["encrypted_html"] += 1
            elif why != "no staticryptConfig (plain page)":
                violations.append((rel, "not exact StatiCrypt output: " + why))
            elif in_bundle:
                violations.append((rel, "plain HTML inside a pre-encrypted bundle"))
            elif matches_any(rel, manifest.get("public_plain")):
                counts["plain_html_allowed"] += 1
            else:
                violations.append((rel, "plain HTML not listed in public_plain"))
        elif kind == "data":
            if matches_any(rel, manifest.get("public_data")):
                counts["data_allowed"] += 1
            else:
                violations.append((rel, "data file not listed in public_data"))
        elif kind == "review":
            if matches_any(rel, manifest.get("public_files")):
                counts["files_allowed"] += 1
            else:
                violations.append((rel, "review-required file type not listed in public_files"))
        else:
            counts["assets"] += 1
    counts["bundles"] = len(bundles)
    return violations, counts

# ---- release-guard shared block end ----

IN_CI = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))


# ---------------------------------------------------------------- passwords
def derive_password(master_secret: str, relative_path: str) -> str:
    digest = hmac.new(master_secret.encode("utf-8"), relative_path.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest)[:24].decode("ascii")


# ---------------------------------------------------------------- fingerprint
def file_fingerprint(src: Path, password: str, template_bytes: bytes, config_bytes: bytes) -> str:
    """Everything that changes the encrypted output. Timestamps are not part of it, so a password,
    template, salt or tool change with unchanged source forces fresh output."""
    h = hashlib.sha256()
    for part in (src.read_bytes(), password.encode("utf-8"), template_bytes, config_bytes, STATICRYPT_VERSION.encode("ascii")):
        h.update(part)
        h.update(b"\x00")
    return h.hexdigest()


def load_fingerprints() -> dict:
    if FINGERPRINT_FILE.exists():
        try:
            return json.loads(FINGERPRINT_FILE.read_text())
        except ValueError:
            return {}
    return {}


def save_fingerprints(m: dict) -> None:
    FINGERPRINT_FILE.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------- release manifest + guard (shared block above)
def load_release_manifest() -> dict:
    """The reviewed allowlist. Same rules and fail-closed checks as .github/scripts/check-release.py."""
    return load_manifest(RELEASE_MANIFEST)


def helper_path() -> Path:
    """render-check.cjs: the repo's copy under .github/scripts/ (what CI runs) or one next to this script."""
    return HELPER or find_helper(WORKSPACE / ".github" / "scripts", Path(__file__).resolve().parent)


_shared_is_staticrypt_output = is_staticrypt_output


def is_staticrypt_output(path: Path, templates=(), helper: Path = None, profiles: dict = None) -> bool:  # noqa: F811 - workspace-aware default
    return _shared_is_staticrypt_output(path, templates, helper or helper_path(), profiles)


def validate_release(output_dir: Path, manifest: dict, templates=(), helper: Path = None) -> list:
    """Same rules as .github/scripts/check-release.py. Returns [(rel, reason)] - paths only, never contents."""
    return check_release(output_dir, manifest, templates, helper or helper_path())[0]


# ---------------------------------------------------------------- source selection (never through a symlink)
def real_file_inside(p: Path, base: Path) -> bool:
    try:
        return p.resolve().is_relative_to(base.resolve())
    except (OSError, ValueError):
        return False


def source_files(base: Path) -> list:
    """Every regular file under base, walked WITHOUT following symlinks. A symlink anywhere in the source
    tree (file or directory) is a hard error: it could materialise a file from outside the tree into the release."""
    out = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for d in list(dirnames):
            if (Path(dirpath) / d).is_symlink():
                sys.exit(f"ERROR: {(Path(dirpath) / d).relative_to(base).as_posix()}/ is a symlinked directory inside {base.name}/ - sources must be real files")
        for f in filenames:
            p = Path(dirpath) / f
            if p.is_symlink() or not real_file_inside(p, base):
                sys.exit(f"ERROR: {p.relative_to(base).as_posix()} is a symlink inside {base.name}/ - sources must be real files")
            out.append(p)
    return sorted(out)


TEMPLATES = []      # the manifest's approved template files, resolved in main() - the ONLY templates any check accepts
PROFILES = {}       # the manifest's label profiles (plus the built-in default), resolved in main()
HELPER = None       # render-check.cjs, resolved in main()


def resolve_templates(manifest: dict) -> list:
    """The one approval set, from the manifest only. The local scripts/encrypt/template.html is used ONLY when the
    manifest lists its path and its digest; otherwise the run stops and tells the owner what to add. A symlinked or
    missing template_paths entry already blocked in candidate_templates()."""
    approved = approved_template_files(manifest, WORKSPACE)
    if TEMPLATE.exists() or TEMPLATE.is_symlink():
        if TEMPLATE.is_symlink():
            sys.exit(f"ERROR: {TEMPLATE.relative_to(WORKSPACE).as_posix()} is a symlink - the template must be a real file inside the repo")
        rel = TEMPLATE.relative_to(WORKSPACE).as_posix()
        if TEMPLATE.resolve() not in [t.resolve() for t in approved]:
            sys.exit(f"ERROR: {rel} is not an approved template. After reviewing it, add its sha256 {sha256_file(TEMPLATE)} to "
                     f"\"approved_templates\" and \"{rel}\" to \"template_paths\" in {RELEASE_MANIFEST.name}. "
                     "Until then nothing is encrypted with it and nothing built from it passes.")
    return approved


# ---------------------------------------------------------------- staticrypt
def encrypt_file(src: Path, output_dir: Path, password: str) -> bool:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["npx", "--yes", STATICRYPT_PKG, str(src), f"--password={password}", "-d", str(output_dir), "--short"]
    if CONFIG_FILE.exists():
        cmd += ["--config", CONFIG_FILE.name]          # relative: StatiCrypt prefixes ./ to the path
    if TEMPLATE.exists():
        cmd += ["--template", str(TEMPLATE)]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(WORKSPACE))
    if result.returncode != 0:
        # stderr may echo the command line (which carries the password): report the exit code only.
        print(f"    staticrypt failed (exit {result.returncode}); re-run with STATICRYPT_DEBUG=1 on a terminal to see its output", file=sys.stderr)
        if os.environ.get("STATICRYPT_DEBUG") and sys.stderr.isatty() and not IN_CI:
            print(result.stderr.replace(password, "<password>"), file=sys.stderr)
        return False
    out = output_dir / src.name
    return out.exists() and is_staticrypt_output(out, TEMPLATES, HELPER, PROFILES)


def sync_static_assets(manifest: dict) -> tuple:
    """Mirror what Pages needs besides encrypted HTML: .nojekyll, the EXTRA_ASSETS chrome, and non-HTML
    files under the source dir. Data files (json, csv, xlsx, md, ...) ship ONLY when public_data allows them.
    Returns (copied, refused)."""
    copied, refused = [], []
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    nojekyll = OUTPUT_DIR / ".nojekyll"
    if not nojekyll.exists():
        nojekyll.touch()
    copied.append(".nojekyll")
    for folder, names in EXTRA_ASSETS:
        for name in names:
            src = WORKSPACE / folder / name
            if src.is_symlink() or (src.exists() and not real_file_inside(src, WORKSPACE / folder)):
                sys.exit(f"ERROR: {folder}/{name} is a symlink or points outside {folder}/ - assets must be real files")
            if src.exists():
                dst = OUTPUT_DIR / folder / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst, follow_symlinks=False)
                copied.append(f"{folder}/{name}")
    if SOURCE_DIR.exists():
        for src in source_files(SOURCE_DIR):
            if src.suffix.lower() in HTML_EXT:
                continue
            rel = src.relative_to(SOURCE_DIR).as_posix()
            kind = classify(src)
            if forbidden_reason(rel, manifest.get("never")) or (kind == "data" and not matches_any(rel, manifest.get("public_data"))) \
                    or (kind == "review" and not matches_any(rel, manifest.get("public_files"))):
                refused.append(rel)
                continue
            dst = OUTPUT_DIR / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst, follow_symlinks=False)
            copied.append(rel)
    return copied, refused


# ---------------------------------------------------------------- main
def resolve_mode(args) -> tuple:
    """Return (mode, secret). Never prints either value."""
    override = os.environ.get("ENCRYPT_PASSWORD", "").strip()
    master = os.environ.get("ENCRYPT_SECRET", "").strip()
    if getattr(args, "derived", False):
        if not ALLOW_DERIVED:
            sys.exit("ERROR: --derived is not available in this repo (single portal password only).")
        if not master:
            sys.exit("ERROR: --derived needs ENCRYPT_SECRET in .env (1Password: the repo's master secret item).")
        return "derived", master
    if DEFAULT_MODE == "shared":
        if not override:
            sys.exit("ERROR: ENCRYPT_PASSWORD (the shared password for this repo) is not set. Add it to .env from the 1Password item named in CLAUDE.md"
                     + (", or pass --derived for a page that deliberately needs its own password." if ALLOW_DERIVED else "."))
        return "shared", override
    if override:
        return "shared", override
    if not master:
        sys.exit("ERROR: ENCRYPT_SECRET is not set. Add ENCRYPT_SECRET=<long random value> to .env in the repo root (then copy it to 1Password).")
    return "derived", master


def main():
    parser = argparse.ArgumentParser(description="Encrypt public-encrypted/ into the Pages release folder and validate the release.")
    parser.add_argument("--show", action="store_true", help="report mode and counts; with --reveal on a terminal, the password table")
    parser.add_argument("--reveal", action="store_true", help="with --show: print the per-file passwords (TTY only, refused in CI)")
    parser.add_argument("--skip-unchanged", action="store_true", help="skip pages whose fingerprint (source+password+template+salt+tool) is current")
    parser.add_argument("--file", metavar="FILENAME", help="one file only (relative path or basename)")
    if ALLOW_DERIVED and DEFAULT_MODE == "shared":
        parser.add_argument("--derived", action="store_true", help="give the page(s) a derived per-file password instead of the shared one")
    args = parser.parse_args()

    mode, secret = resolve_mode(args)
    if not SOURCE_DIR.exists():
        sys.exit(f"ERROR: source directory '{SOURCE_DIR}' does not exist.")

    global TEMPLATES, PROFILES, HELPER
    HELPER = helper_path()
    html_files = [f for f in source_files(SOURCE_DIR) if f.suffix.lower() in HTML_EXT]
    rel_paths = {f: f.relative_to(SOURCE_DIR).as_posix() for f in html_files}
    if args.file:
        html_files = [f for f in html_files if rel_paths[f] == args.file or f.name == args.file]
        if not html_files:
            sys.exit(f"ERROR: '{args.file}' not found in {SOURCE_DIR}")

    manifest = load_release_manifest()
    TEMPLATES = resolve_templates(manifest)
    PROFILES = manifest.get("label_profiles", {})
    passwords = {rel_paths[f]: (secret if mode == "shared" else derive_password(secret, rel_paths[f])) for f in html_files}

    if args.show:
        where = "ENCRYPT_PASSWORD in .env (one shared password)" if mode == "shared" else "derived per file from ENCRYPT_SECRET in .env"
        print(f"\n{len(html_files)} page(s) under {SOURCE_DIR.relative_to(WORKSPACE)}/ - passwords: {where}.")
        if not args.reveal:
            print("Values are not printed. On a terminal, add --reveal to see the table; the secret itself lives in 1Password.")
            return
        if IN_CI or not sys.stdout.isatty():
            sys.exit("REFUSED: --reveal prints passwords and this is not an interactive terminal (or CI is set).")
        print(f"\n  {'File':<60} Password")
        print(f"  {'-' * 60} {'-' * 24}")
        for rel, pwd in passwords.items():
            print(f"  {rel:<60} {pwd}")
        print("\nShare one password per recipient. Never paste this table into a chat, a doc or a commit.")
        return

    template_bytes = TEMPLATE.read_bytes() if TEMPLATE.exists() else b""
    config_bytes = CONFIG_FILE.read_bytes() if CONFIG_FILE.exists() else b""
    fingerprints = load_fingerprints()

    passthrough = manifest.get("passthrough", [])
    # One exact-render pass over every source page and every existing output (the same check CI runs).
    verdicts = exact_envelope_check(list(html_files) + [OUTPUT_DIR / rel_paths[f] for f in html_files if (OUTPUT_DIR / rel_paths[f]).is_file()], TEMPLATES, HELPER, PROFILES)
    enc = lambda p: verdicts.get(str(p), (False, "", ""))[0]
    todo, skipped, verbatim = [], [], []
    for src in html_files:
        rel = rel_paths[src]
        out = OUTPUT_DIR / rel
        if matches_any(rel, passthrough):
            if not enc(src):
                sys.exit(f"ERROR: {rel} is listed under passthrough but is not StatiCrypt output - it is plaintext. Remove it from the list or encrypt it.")
            verbatim.append(src)
            continue
        if enc(src):
            sys.exit(f"ERROR: {rel} is already StatiCrypt output (no plaintext source). Re-encrypting would double-wrap it. "
                     f"List it under \"passthrough\" in {RELEASE_MANIFEST.name} to copy it verbatim, after review.")
        fp = file_fingerprint(src, passwords[rel], template_bytes, config_bytes)
        if args.skip_unchanged and fingerprints.get(rel) == fp and enc(out):
            skipped.append(rel)
            continue
        todo.append((src, rel, fp))

    template_note = f" (template: {TEMPLATE.name})" if TEMPLATE.exists() else " (default template)"
    print(f"\nEncrypting {len(todo)} page(s){template_note}, {len(skipped)} unchanged, {len(verbatim)} passthrough -> {OUTPUT_DIR.relative_to(WORKSPACE)}/")

    failed = []
    for src, rel, fp in todo:
        print(f"  {rel} ...", end=" ", flush=True)
        ok = encrypt_file(src, OUTPUT_DIR / Path(rel).parent, passwords[rel])
        print("OK" if ok else "FAILED")
        if ok:
            fingerprints[rel] = fp
        else:
            failed.append(rel)
            fingerprints.pop(rel, None)
    for src in verbatim:
        rel = rel_paths[src]
        dst = OUTPUT_DIR / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst, follow_symlinks=False)
        print(f"  {rel} ... copied verbatim (passthrough)")
    save_fingerprints(fingerprints)

    refused = []
    if SYNC_ASSETS:
        copied, refused = sync_static_assets(manifest)
        print(f"\nAssets mirrored into {OUTPUT_DIR.relative_to(WORKSPACE)}/: {len(copied)}")
        if refused:
            print(f"Refused (not in public_data / public_files): {len(refused)} - " + ", ".join(refused), file=sys.stderr)

    violations = validate_release(OUTPUT_DIR, manifest, TEMPLATES, HELPER)
    if violations:
        print(f"\nRELEASE BLOCKED: {len(violations)} file(s) in {OUTPUT_DIR.relative_to(WORKSPACE)}/ are not allowed by {RELEASE_MANIFEST.name}:", file=sys.stderr)
        for rel, why in violations:
            print(f"  {rel}  -  {why}", file=sys.stderr)
    refused = refused if SYNC_ASSETS else []
    if failed or violations or refused:
        if failed:
            print(f"\nWARNING: {len(failed)} page(s) failed to encrypt", file=sys.stderr)
        if refused:
            print(f"WARNING: {len(refused)} file(s) refused - data files go under public_data, downloads and other formats under public_files in {RELEASE_MANIFEST.name} after review, or move them out of public-encrypted/", file=sys.stderr)
        sys.exit(1)
    print(f"\nDone. {len(todo)} encrypted, {len(skipped)} unchanged, {len(verbatim)} passthrough; release validated. "
          f"Passwords: {'ENCRYPT_PASSWORD' if mode == 'shared' else 'derived from ENCRYPT_SECRET'} (never printed; --show --reveal on a terminal).")


if __name__ == "__main__":
    main()
