#!/usr/bin/env node
// Exact StatiCrypt envelope check for the release guard.
//
// A page counts as encrypted ONLY if it is byte-for-byte what StatiCrypt 3.5.4 renders from an approved
// template plus narrowly permitted substitutions. Nothing is inferred from sizes or markers: the page is
// parsed against the template, the runtime block must equal the library's own build, the config must be
// the exact JSON the library writes, every label field (title, instructions, button, placeholder, remember,
// error, the 2 toggles, the 2 colours) must equal the value of ONE approved label profile - the library's own
// CLI defaults (profile "default") or a profile the reviewed manifest lists - and the template is re-rendered
// and compared to the file. Any appended text, comment, extra script, transplanted runtime, fabricated config
// or unreviewed label text therefore fails because the bytes differ or no profile matches. Nothing is inferred
// from syntax, length or round-trip equality of a free-text field.
//
// stdin:  {"files": ["<abs path>", ...], "templates": ["<abs template path>", ...], "profiles": {"<name>": {"template_title": "...", ...}}}
//         (templates: the manifest-approved set; the library default template is always added first.
//          profiles: the manifest's label_profiles; "default" is built in and cannot be redefined)
// stdout: {"library": {...}, "templates": [...], "profiles": ["default", ...],
//          "results": [{"file", "ok", "template_sha256", "profile", "reason"}]}
// Exit 0 when the helper ran (per-file verdicts are in the JSON), 2 when the pinned library is absent.
// Never prints file contents.
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execSync } = require("node:child_process");

const PINNED_VERSION = "3.5.4";

function findLibrary() {
    // An explicit STATICRYPT_LIB is authoritative: it is used alone, so CI and tests get exactly the copy they name.
    const candidates = [];
    if (process.env.STATICRYPT_LIB) {
        candidates.push(process.env.STATICRYPT_LIB);
    } else try {
        const root = execSync("npm root -g", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
        if (root) candidates.push(path.join(root, "staticrypt"));
    } catch (e) { /* npm absent: fall through */ }
    if (!process.env.STATICRYPT_LIB) {
        candidates.push("/usr/local/lib/node_modules/staticrypt", "/usr/lib/node_modules/staticrypt",
            path.join(process.env.HOME || "", ".npm-global/lib/node_modules/staticrypt"));
    }
    for (const c of candidates) {
        const pkg = path.join(c, "package.json");
        if (!fs.existsSync(pkg)) continue;
        let version;
        try { version = JSON.parse(fs.readFileSync(pkg, "utf8")).version; } catch (e) { continue; }
        if (version === PINNED_VERSION) return c;
    }
    return null;
}

const LIB = findLibrary();
if (!LIB) {
    process.stdout.write(JSON.stringify({ error: `staticrypt ${PINNED_VERSION} is not installed (set STATICRYPT_LIB or run: npm i -g staticrypt@${PINNED_VERSION})` }));
    process.exit(2);
}
const { renderTemplate } = require(path.join(LIB, "lib", "formater.js"));
const { buildStaticryptJS } = require(path.join(LIB, "cli", "helpers.js"));
const DEFAULT_TEMPLATE = path.join(LIB, "lib", "password_template.html");
const RUNTIME = buildStaticryptJS();

// Placeholder grammar used by lib/formater.js: /*[|key|]*/0 with optional whitespace before the 0.
const PLACEHOLDER = /\/\*\[\|\s*(\w+)\s*\|]\*\/\s*0/g;
// The label fields the CLI lets an operator set. A page passes only when EVERY label field it carries equals
// the value of one approved profile. The built-in profile "default" is the library's own CLI defaults
// (cli/helpers.js, staticrypt 3.5.4); a reviewed manifest may add named profiles. There is no syntax or length
// rule: a value that is not an approved profile value is not a substitution.
const LABEL_FIELDS = ["template_title", "template_instructions", "template_button", "template_placeholder",
    "template_remember", "template_error", "template_toggle_show", "template_toggle_hide",
    "template_color_primary", "template_color_secondary"];
const BUILTIN_PROFILES = {
    default: {
        template_title: "Protected Page", template_instructions: "", template_button: "DECRYPT",
        template_placeholder: "Password", template_remember: "Remember me", template_error: "Bad password!",
        template_toggle_show: "Show password", template_toggle_hide: "Hide password",
        template_color_primary: "#4CAF50", template_color_secondary: "#76B852",
    },
};
const CONFIG_KEYS = ["staticryptEncryptedMsgUniqueVariableName", "isRememberEnabled", "rememberDurationInDays", "staticryptSaltUniqueVariableName"];

function splitTemplate(text) {
    // -> [{lit}, {key}, {lit}, ...] in order; a key not in the CLI data set renders as its own name.
    const parts = []; let last = 0; let m;
    PLACEHOLDER.lastIndex = 0;
    while ((m = PLACEHOLDER.exec(text)) !== null) {
        parts.push({ lit: text.slice(last, m.index) });
        parts.push({ key: m[1] });
        last = m.index + m[0].length;
    }
    parts.push({ lit: text.slice(last) });
    return parts;
}

function parseAgainst(parts, page) {
    // Sequential literal matching: every literal segment must appear in order; the text between two
    // literals is the substitution for the key between them. Returns {values} or {reason}.
    const values = {}; let pos = 0;
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if ("lit" in part) {
            if (i === 0) {
                if (!page.startsWith(part.lit)) return { reason: "page does not start like the template" };
                pos = part.lit.length;
            } else if (i === parts.length - 1) {
                if (!page.endsWith(part.lit) || page.length - part.lit.length < pos) return { reason: "page does not end like the template" };
                const key = parts[i - 1].key; const val = page.slice(pos, page.length - part.lit.length);
                if (key in values && values[key] !== val) return { reason: `repeated field ${key} differs` };
                values[key] = val; pos = page.length;
            } else {
                const idx = part.lit.length ? page.indexOf(part.lit, pos) : pos;
                if (idx < 0) return { reason: "template structure not found in page" };
                const key = parts[i - 1].key; const val = page.slice(pos, idx);
                if (key in values && values[key] !== val) return { reason: `repeated field ${key} differs` };
                values[key] = val; pos = idx + part.lit.length;
            }
        }
    }
    return { values };
}

function checkValues(values, profiles) {
    const labels = {};
    for (const [key, val] of Object.entries(values)) {
        if (key === "js_staticrypt") {
            if (val !== RUNTIME) return `runtime block is not the staticrypt ${PINNED_VERSION} build`;
        } else if (key === "staticrypt_config") {
            let cfg;
            try { cfg = JSON.parse(val); } catch (e) { return "staticryptConfig is not valid JSON"; }
            if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) return "staticryptConfig is not an object";
            const keys = Object.keys(cfg);
            if (keys.length !== CONFIG_KEYS.length || CONFIG_KEYS.some((k, i) => keys[i] !== k)) return "staticryptConfig does not have exactly the 4 library fields in order";
            if (typeof cfg.staticryptEncryptedMsgUniqueVariableName !== "string" || !/^[0-9a-f]{96,}$/.test(cfg.staticryptEncryptedMsgUniqueVariableName)) return "encrypted message is not the library's hex form";
            if (!/^[0-9a-f]{32}$/.test(cfg.staticryptSaltUniqueVariableName || "")) return "salt is not a 32-hex value";
            if (typeof cfg.isRememberEnabled !== "boolean") return "isRememberEnabled is not a boolean";
            if (!Number.isInteger(cfg.rememberDurationInDays) || cfg.rememberDurationInDays < 0) return "rememberDurationInDays is not a non-negative integer";
            if (JSON.stringify(cfg) !== val) return "staticryptConfig is not the exact JSON the library writes";
            values.__config = cfg;
        } else if (key === "is_remember_enabled") {
            if (val !== "true" && val !== "false") return "is_remember_enabled is not a boolean literal";
        } else if (LABEL_FIELDS.includes(key)) {
            labels[key] = val;
        } else {
            // A placeholder the CLI never fills renders as its own name (formater.js behaviour).
            if (val !== key) return `unexpected substitution for ${key}`;
        }
    }
    if (values.__config && String(values.__config.isRememberEnabled) !== values.is_remember_enabled) return "is_remember_enabled does not match the config";
    // Every label field the page carries must equal one approved profile's value for that field. The reason
    // names the field, never the text.
    const fields = Object.keys(labels);
    if (fields.length) {
        let best = null; let bestMiss = null;
        for (const [name, prof] of Object.entries(profiles)) {
            const miss = fields.filter((f) => !(f in prof) || prof[f] !== labels[f]);
            if (miss.length === 0) { values.__profile = name; bestMiss = null; break; }
            if (bestMiss === null || miss.length < bestMiss.length) { best = name; bestMiss = miss; }
        }
        if (bestMiss !== null) return `label ${bestMiss[0]} is not an approved profile value (closest profile: ${best})`;
    } else {
        values.__profile = "template";  // the template carries its labels as fixed text; its digest is the approval
    }
    return null;
}

function checkFile(file, templates, profiles) {
    let page;
    try { page = fs.readFileSync(file, "utf8"); } catch (e) { return { file, ok: false, reason: "unreadable" }; }
    if (!page.includes("staticryptConfig")) return { file, ok: false, reason: "no staticryptConfig (plain page)" };
    // Report the most specific reason: a template whose structure matched but whose values or render
    // failed beats "does not start like the template" from an unrelated template.
    let structural = "no approved template matches this page's structure"; let specific = null;
    for (const t of templates) {
        const text = t.text; const parts = t.parts;
        const parsed = parseAgainst(parts, page);
        if (parsed.reason) { structural = parsed.reason; continue; }
        const bad = checkValues(parsed.values, profiles);
        if (bad) { specific = specific || bad; continue; }
        const data = { ...parsed.values };
        delete data.__config; delete data.__profile;
        data.staticrypt_config = parsed.values.__config;  // renderTemplate JSON.stringifies objects
        const rendered = renderTemplate(text, data);
        if (rendered !== page) { specific = specific || "page is not byte-identical to the template render"; continue; }
        return { file, ok: true, template_sha256: t.sha256, profile: parsed.values.__profile };
    }
    return { file, ok: false, reason: specific || structural };
}

function loadTemplates(paths) {
    const out = [];
    for (const p of paths) {
        let text;
        try { text = fs.readFileSync(p, "utf8"); } catch (e) { continue; }
        out.push({ path: p, text, parts: splitTemplate(text), sha256: crypto.createHash("sha256").update(text).digest("hex") });
    }
    return out;
}

function main() {
    const input = JSON.parse(fs.readFileSync(0, "utf8") || "{}");
    const templatePaths = [DEFAULT_TEMPLATE].concat((input.templates || []).filter((p) => p && p !== DEFAULT_TEMPLATE));
    const templates = loadTemplates(templatePaths);
    const profiles = { ...BUILTIN_PROFILES };
    for (const [name, prof] of Object.entries(input.profiles || {})) {
        if (name in BUILTIN_PROFILES || !prof || typeof prof !== "object") continue;  // the guard refuses these before calling
        const clean = {};
        for (const f of LABEL_FIELDS) if (typeof prof[f] === "string") clean[f] = prof[f];
        profiles[name] = clean;
    }
    const results = (input.files || []).map((f) => checkFile(f, templates, profiles));
    process.stdout.write(JSON.stringify({
        library: { version: PINNED_VERSION, root: LIB, runtime_sha256: crypto.createHash("sha256").update(RUNTIME).digest("hex") },
        templates: templates.map((t) => ({ path: t.path, sha256: t.sha256 })),
        profiles: Object.keys(profiles),
        results,
    }));
}

main();
