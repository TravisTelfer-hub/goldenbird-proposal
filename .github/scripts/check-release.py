#!/usr/bin/env python3
"""check-release.py - release guard for a GitHub Pages artefact (python3 stdlib + node for the exact check).

Walks the release root and fails (exit 1) when the release would publish something the reviewed
manifest does not allow. It prints PATHS and reasons only, never file contents.

    python3 .github/scripts/check-release.py --root docs --manifest release-manifest.json
    python3 .github/scripts/check-release.py --root docs --manifest release-manifest.json --plan

Every file under --root is classified, and every class has a rule. Nothing passes because of its
extension alone:
  forbidden   a path whose NAME matches the `never` names (CLAUDE.md, .env*, settings.local.json,
              *.lock.json, passwords*, *-raw.json, Makefile, lefthook.yml, .gitignore, .staticrypt.json,
              release-manifest.json, encrypt-manifest.json, .DS_Store) or that sits under a `never`
              directory at ANY depth (scripts, public-encrypted, private, .git, .github, .claude,
              node_modules, _internal). Symlinks (file or directory) are forbidden outright.
  html        .html/.htm must be EXACT StatiCrypt output (see below) or match `public_plain`
              (a reviewed public page). Inside a `bundles` directory `public_plain` does not apply.
  data        .json .csv .tsv .xlsx .xls .md .txt .yml .yaml .sql .xml .ndjson, and any .js/.mjs whose
              body is JSON, must match `public_data`.
  asset       .css .png .jpg .jpeg .gif .webp .avif .ico .woff .woff2 .ttf .otf .eot, plus the Pages
              control files `.nojekyll` and `CNAME`: pass. (CSS is reviewed by the asset selection of
              the build, not by this guard - see the README.)
  review      everything else (js, mjs, map, pdf, svg, docx, zip, py, sh, toml, ini, files without an
              extension ...) must match `public_files` - a reviewed list of downloads and payload-bearing
              formats. JavaScript is review-required because a record wrapped in `window.x = {...}` is
              data with a different extension.

EXACT StatiCrypt output means: the page is byte-for-byte what staticrypt 3.5.4 renders from an
approved template plus narrowly permitted substitutions. The check is done by `render-check.cjs`
(next to this script) with the pinned library itself:
  - the page is parsed against the template's placeholders; the runtime block must equal the
    library's own build; `staticryptConfig` must be exactly the 4-field JSON the library writes
    (32-hex salt, hex ciphertext, boolean remember flag, integer days); every label field the page
    carries (title, instructions, button, placeholder, remember, error, the 2 toggles, the 2 colours)
    must equal the value of ONE approved label profile - the library's own CLI defaults (built-in
    profile `default`) or a profile listed in the manifest's `label_profiles`. No syntax or length
    rule: an unreviewed label value is not a substitution, and the failure names the field, never
    the text;
  - the template is re-rendered with those values and must equal the file byte for byte, so any
    appended text, comment, extra script, transplanted runtime or fabricated config fails.
  Approved templates = the library's default `password_template.html` (always) plus every file named
  in the manifest's `template_paths` (relative to the manifest) whose SHA-256 is listed in
  `approved_templates`. Every `template_paths` entry must be a regular file inside the repo with no
  symlink at any ancestor or final component; a missing, symlinked or escaping entry BLOCKS the
  release even when the library default would otherwise satisfy every page. The same approval set
  is used here, in the encryptor's passthrough / already-encrypted / skip decisions and in its final
  validation: the encryptor does not trust its local template until its digest is listed. `--plan`
  prints the SHA-256 of each candidate so an owner can list it after review. The library must be
  installed at the pinned version (`npm i -g staticrypt@3.5.4`, or STATICRYPT_LIB=<its directory>);
  if it is absent the guard fails closed with that message.

Manifest (`release-manifest.json`, next to the repo root; globs are relative to the release root,
`*` also crosses `/`, a trailing `/` means the directory and everything under it). Unknown keys,
duplicate keys, non-list values, a missing file, invalid JSON, or a `release_root` that is not the
directory being checked all BLOCK the release (fail closed):
  {"release_root": "docs", "public_plain": ["training/*", "index.html"], "public_data": ["assets/*.json"],
   "public_files": ["downloads/*.pdf"], "bundles": ["reports/legacy/"], "passthrough": [], "never": [],
   "approved_templates": ["<sha256 of scripts/encrypt/template.html>"], "template_paths": ["scripts/encrypt/template.html"],
   "label_profiles": {"<name>": {"template_title": "...", "template_button": "...", ...}}}
`passthrough` is read by the encryptor (source files copied verbatim after the same exact check), not
by this guard. `label_profiles` maps a profile name to exact strings for the 10 label fields; `default`
is built in (the library's CLI defaults) and cannot be redefined; a page whose template carries its
labels as fixed text (the Webprofits template) needs no profile, its digest is the approval.
"""
import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

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


def root_matches_manifest(root: Path, manifest_path: Path, manifest: dict) -> bool:
    """The manifest certifies one directory. A symlinked release_root is refused: it could point anywhere."""
    declared = manifest_path.resolve().parent / manifest["release_root"]
    if declared.is_symlink():
        return False
    return declared.resolve() == root.resolve()


def main() -> int:
    ap = argparse.ArgumentParser(description="Fail a Pages release that contains unapproved plaintext, data or files.")
    ap.add_argument("--root", required=True, help="release directory (what Pages will serve)")
    ap.add_argument("--manifest", default="release-manifest.json", help="reviewed allowlist (default: release-manifest.json)")
    ap.add_argument("--plan", action="store_true", help="report what WOULD be blocked, grouped by reason, and exit 0 (migration dry run)")
    args = ap.parse_args()
    root = Path(args.root)
    if root.is_symlink() or not root.is_dir():
        print(f"RELEASE BLOCKED: release root {root} is missing or a symlink", file=sys.stderr)
        return 1
    manifest_path = Path(args.manifest)
    manifest = load_manifest(manifest_path)
    if not root_matches_manifest(root, manifest_path, manifest):
        print(f"RELEASE BLOCKED: manifest release_root is '{manifest['release_root']}' but '{root}' was given - the guard only certifies the directory the manifest was reviewed for", file=sys.stderr)
        return 1
    base = manifest_path.resolve().parent
    helper = find_helper()
    candidates = candidate_templates(manifest, base)
    templates = [p for p, _, ok in candidates if ok]
    violations, counts = check_release(root, manifest, templates, helper)
    if args.plan:
        by_reason = {}
        for rel, why in violations:
            by_reason.setdefault(why.split(":")[0], []).append(rel)
        print(f"plan: {counts['files']} files in {root}; {len(violations)} would be blocked")
        for p, sha, ok in candidates:
            print(f"  template {p.relative_to(base).as_posix()} sha256 {sha} - {'approved' if ok else 'NOT in approved_templates (list it after review)'}")
        print(f"  label profiles: default (built in)" + "".join(f", {n}" for n in manifest.get("label_profiles", {})))
        for why, rels in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
            print(f"  {len(rels):5d}  {why}")
            for rel in rels:
                print(f"           {rel}")
        return 0
    if violations:
        print(f"RELEASE BLOCKED: {len(violations)} file(s) in {root} are not allowed by {args.manifest}:", file=sys.stderr)
        for rel, why in violations:
            print(f"  {rel}  -  {why}", file=sys.stderr)
        print("Fix: encrypt the page with the pinned tool and an approved template, move the file out of the release root, or list it in the manifest after review.", file=sys.stderr)
        return 1
    print(f"release ok: {counts['files']} files in {root} - {counts['encrypted_html']} encrypted pages, "
          f"{counts['plain_html_allowed']} reviewed plain pages, {counts['data_allowed']} allowed data files, "
          f"{counts['files_allowed']} allowed review-required files, {counts['assets']} assets, {counts['bundles']} bundle(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
