# cipherbloom:ignore-file  (describes risky patterns in prose and regexes, not real calls)
"""The agent: look at the project, decide what to check, run it, chase down each
finding, and hand back a short list of what to fix first.

The built-in brain is plain Python. No AI, no API key, nothing leaves the machine.
An optional LLM brain (see llm.py) can review the same results on top of that.

Loop:  profile -> plan -> act -> investigate -> correlate -> prioritise
Every step is written to a trace so you can see why it said what it said.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from .engine import STAGES, run_scan
from .files import iter_files, read_text, rel
from .models import SEVERITY_WEIGHT, sort_findings

JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
WEB_DIRS = ("public/", "static/", "www/", "dist/", "assets/", "client/", "frontend/")
SAMPLE_PARTS = ("test", "tests", "spec", "fixture", "fixtures", "example", "examples",
                "sample", "samples", "demo", "docs", "mock", "mocks")
MANIFESTS = ("requirements.txt", "pyproject.toml", "Pipfile", "package.json", "setup.py")
FRAMEWORKS = {
    "flask": "Flask", "django": "Django", "fastapi": "FastAPI", "express": "Express",
    "next": "Next.js", "react": "React", "aiogram": "aiogram", "telegram": "Telegram bot",
    "pyrogram": "Pyrogram", "kurigram": "Kurigram", "discord": "Discord bot",
}
ENTRY_NAMES = ("app.py", "main.py", "server.py", "bot.py", "manage.py", "wsgi.py",
               "index.js", "server.js", "app.js", "main.js")

# Places where a user could be handing us text, per language.
PY_SOURCES = re.compile(
    r"request\.(?:args|form|json|values|data|get_json|files|headers|cookies)|"
    r"\binput\s*\(|sys\.argv|\bargparse\b|\.get_json\(|message\.text|update\.message|"
    r"event\.|query_params|path_params|\bBody\(|\bForm\(")
JS_SOURCES = re.compile(
    r"req\.(?:body|query|params|headers|cookies)|process\.argv|location\.(?:search|hash|href)|"
    r"document\.(?:cookie|referrer|URL)|window\.name|event\.data|postMessage|"
    r"\.value\b|searchParams|URLSearchParams")

CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.6, "low": 0.25, "ai-suggested": 0.5, "": 0.6}


@dataclass
class Step:
    phase: str
    text: str


@dataclass
class Chain:
    id: str
    title: str
    why: str
    findings: list = field(default_factory=list)  # "file:line rule" strings


@dataclass
class PlanItem:
    order: int
    title: str
    why: str
    how: str
    refs: list = field(default_factory=list)


@dataclass
class AgentResult:
    root: str
    brain: str
    profile: dict
    steps: list
    checks: list
    findings: list
    chains: list
    plan: list
    notes: list
    seconds: float = 0.0

    def to_dict(self):
        return {
            "brain": self.brain, "profile": self.profile,
            "trace": [{"phase": s.phase, "text": s.text} for s in self.steps],
            "chains": [c.__dict__ for c in self.chains],
            "fix_plan": [p.__dict__ for p in self.plan],
            "notes": self.notes,
        }


# ── 1. profile ──────────────────────────────────────────────────────────────
def profile_project(root):
    info = {"languages": [], "frameworks": [], "manifests": [], "entry_points": [],
            "web_dirs": [], "env_files": [], "is_git": False, "files": 0}
    if not os.path.isdir(root):
        return info
    langs, manifest_text = set(), ""
    for path in iter_files(root):
        info["files"] += 1
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lower()
        relpath = rel(path, root)
        if ext == ".py":
            langs.add("Python")
        elif ext in JS_EXT:
            langs.add("JavaScript/TypeScript")
        elif ext in (".html", ".htm"):
            langs.add("HTML")
        if name in MANIFESTS and name not in info["manifests"]:
            info["manifests"].append(name)
            manifest_text += (read_text(path) or "").lower()[:20000]
        if name in ENTRY_NAMES and len(info["entry_points"]) < 6:
            info["entry_points"].append(relpath)
        if name.lower().startswith(".env") and not name.lower().endswith((".example", ".sample", ".template")):
            info["env_files"].append(relpath)
        if name == "Dockerfile":
            langs.add("Docker")
    for d in ("public", "static", "www", "dist", "assets"):
        if os.path.isdir(os.path.join(root, d)):
            info["web_dirs"].append(d + "/")
    info["languages"] = sorted(langs)
    info["frameworks"] = sorted({label for key, label in FRAMEWORKS.items()
                                 if re.search(r"(?<![a-z])%s(?![a-z])" % re.escape(key), manifest_text)})
    info["is_git"] = os.path.isdir(os.path.join(root, ".git"))
    return info


# ── 2. plan ─────────────────────────────────────────────────────────────────
def make_plan(profile, options, live_target):
    """Decide which checks are worth running and say why. Returns (stage_keys, steps)."""
    keys, steps = [], []
    langs = set(profile["languages"])
    code = bool({"Python", "JavaScript/TypeScript"} & langs)
    for key, label, _fn in STAGES:
        if key == "secrets":
            keys.append(key)
            steps.append(Step("plan", "Run secrets: every project can leak a key."))
        elif key == "git":
            if profile["is_git"] or profile["env_files"]:
                keys.append(key)
                steps.append(Step("plan", "Run git hygiene: %s." % (
                    "this is a git repo" if profile["is_git"] else "there are .env files to protect")))
            else:
                steps.append(Step("plan", "Skip git hygiene: no git repo and no .env files."))
        elif key in ("syntax", "risky"):
            if code:
                keys.append(key)
                steps.append(Step("plan", "Run %s: %s code found." % (label, " and ".join(sorted(langs & {"Python", "JavaScript/TypeScript"})))))
            else:
                steps.append(Step("plan", "Skip %s: no Python or JavaScript files." % label))
        elif key == "deps":
            if profile["manifests"]:
                keys.append(key)
                steps.append(Step("plan", "Run dependencies: found %s." % ", ".join(profile["manifests"])))
            else:
                steps.append(Step("plan", "Skip dependencies: no manifest file."))
    if live_target:
        steps.append(Step("plan", "Run the live localhost check on %s (consent already given)." % live_target))
    return keys, steps


# ── 3. investigate ──────────────────────────────────────────────────────────
def _git(root, *args):
    if not shutil.which("git"):
        return None
    try:
        return subprocess.run(["git", "-C", root] + list(args), capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def git_exposure(root, relpath):
    """('tracked'|'in-history'|'ignored'|'untracked'|'unknown', detail)."""
    if not os.path.isdir(os.path.join(root, ".git")):
        return "unknown", ""
    r = _git(root, "ls-files", "--error-unmatch", "--", relpath)
    if r is not None and r.returncode == 0:
        return "tracked", ""
    h = _git(root, "log", "--all", "--oneline", "-1", "--", relpath)
    if h is not None and h.returncode == 0 and h.stdout.strip():
        return "in-history", ""
    c = _git(root, "check-ignore", "-q", "--", relpath)
    if c is not None and c.returncode == 0:
        return "ignored", ""
    return "untracked", ""


def _is_sample_path(relpath):
    parts = relpath.lower().split("/")
    stem = parts[-1].rsplit(".", 1)[0]
    return any(p in SAMPLE_PARTS for p in parts[:-1]) or stem.startswith(("test_", "example", "sample", "demo")) \
        or stem.endswith(("_test", ".test", ".spec"))


FUNC_START = re.compile(r"^\s*(?:async\s+)?def\s|^\s*(?:export\s+)?(?:async\s+)?function\b|=>\s*\{?\s*$|"
                        r"^\s*(?:app|router)\.(?:get|post|put|delete|patch|use|route)\(")


def _context(root, f, before=12, after=2):
    """The lines around a finding, cut off at the start of the function it sits in."""
    path = os.path.join(root, f.file)
    text = read_text(path) if f.file else None
    if text is None or not f.line:
        return ""
    lines = text.splitlines()
    lo = max(0, f.line - 1 - before)
    for i in range(f.line - 2, lo - 1, -1):
        if FUNC_START.search(lines[i]):
            lo = i
            break
    return "\n".join(lines[lo:f.line + after])


def _note(f, text):
    f.notes = (f.notes + " " + text).strip() if f.notes else text


def investigate(root, findings, profile, steps):
    """Follow up on each finding: is it really exposed, is user input involved, is it sample data?"""
    dup_count = {}
    for f in findings:
        if f.category == "secret" and f.snippet:
            dup_count[f.snippet] = dup_count.get(f.snippet, 0) + 1
    exposure_cache = {}
    for f in findings:
        if f.category == "secret":
            _investigate_secret(root, f, exposure_cache, dup_count)
        elif f.category == "code":
            _investigate_code(root, f)
        elif f.category == "git":
            f.confidence = f.confidence or "high"
            _note(f, "Checked straight from git, not guessed.")
        elif f.category in ("syntax", "live"):
            f.confidence = f.confidence or "high"
        else:
            f.confidence = f.confidence or "medium"
    shown = sum(1 for f in findings if f.notes)
    steps.append(Step("investigate", "Followed up on %d of %d findings (git exposure, user-input flow, sample data)." % (shown, len(findings))))


def _investigate_secret(root, f, cache, dup_count):
    provider = f.rule not in ("hardcoded-secret", "env-file-secret")
    f.confidence = "high" if provider else "medium"
    if _is_sample_path(f.file):
        f.confidence = "low"
        _note(f, "Sits in a test/example/docs path, so it is probably sample data. Check it anyway before you ignore it.")
    if f.file not in cache:
        cache[f.file] = git_exposure(root, f.file)
    state = cache[f.file][0]
    if state == "tracked":
        _note(f, "This file is committed to git, so the secret is already in your repo.")
        if f.confidence == "low" and not _is_sample_path(f.file):
            f.confidence = "medium"
    elif state == "in-history":
        _note(f, "Deleted from the working tree but still in git history. Treat it as leaked.")
    elif state == "ignored":
        _note(f, "File is git-ignored and was never committed, so the secret stays on this machine.")
        if f.rule == "env-file-secret":
            f.confidence = "low"
    elif state == "untracked":
        _note(f, "Not committed yet, but also not git-ignored: one `git add .` away from leaking.")
    if f.file.lower().startswith(WEB_DIRS) or (os.path.splitext(f.file)[1].lower() in (".html", ".htm")):
        _note(f, "Lives in browser-facing code, so every visitor can read it.")
        f.confidence = "high"
    n = dup_count.get(f.snippet, 0)
    if n > 1:
        _note(f, "The same masked value shows up in %d places." % n)


def _investigate_code(root, f):
    ext = os.path.splitext(f.file)[1].lower()
    ctx = _context(root, f)
    sources = JS_SOURCES if ext in JS_EXT else PY_SOURCES
    hit = sources.search(ctx) if ctx else None
    config_rules = {"py-debug-true", "py-verify-false", "py-cors-wildcard", "js-cors-wildcard"}
    if f.rule in config_rules:
        f.confidence = "high"
        if f.rule == "py-debug-true" and "__main__" in ctx:
            f.confidence = "medium"
            _note(f, "Inside an `if __name__ == '__main__'` block, so likely local-only. Make sure production does not use it.")
        return
    if f.rule in ("py-yaml-load", "py-pickle-load"):
        f.confidence = "medium"
        _note(f, "Only a problem if the data can come from outside your own machine.")
    if hit:
        f.confidence = "high"
        _note(f, "User-controlled input (%s) appears in the same function." % hit.group(0).strip())
    elif ctx:
        f.confidence = f.confidence or "medium"
        if f.confidence == "medium" and f.rule not in ("py-yaml-load", "py-pickle-load"):
            f.confidence = "low"
        _note(f, "No obvious user input in the same function. Might be internal-only; trace where the value comes from.")
    else:
        f.confidence = "medium"


# ── 4. correlate ────────────────────────────────────────────────────────────
def correlate(findings):
    chains = []
    env_bad = [f for f in findings if f.rule in ("env-tracked", "env-in-history", "env-not-ignored")]
    env_secrets = [f for f in findings if f.category == "secret"
                   and os.path.basename(f.file).lower().startswith(".env")]
    if env_bad and env_secrets:
        chains.append(Chain(
            "leaked-env", "Your .env can walk out the door with real secrets in it",
            "A .env holding real-looking secrets is not protected by git, so a push, a fork or a zip upload "
            "hands them over.",
            ["%s %s" % (f.location(), f.rule) for f in env_bad + env_secrets][:8]))
    inj = [f for f in findings if f.rule in ("py-eval", "py-exec", "py-shell-true", "py-os-system",
                                              "js-eval", "js-child-process-exec", "py-sql-format")
           and f.confidence == "high"]
    dbg = [f for f in findings if f.rule == "py-debug-true"]
    if inj and dbg:
        chains.append(Chain(
            "injection-plus-debug", "Injectable code plus debug mode is the classic way servers get taken over",
            "Debug pages leak paths and sometimes give a code console, which makes an injection bug much "
            "easier to exploit.",
            ["%s %s" % (f.location(), f.rule) for f in inj + dbg][:8]))
    browser = [f for f in findings if f.category == "secret" and "browser-facing" in f.notes]
    if browser:
        chains.append(Chain(
            "secrets-in-browser", "Secrets are shipped to every visitor's browser",
            "Anything under a public/static folder or in front-end code is downloadable by anyone.",
            ["%s %s" % (f.location(), f.rule) for f in browser][:8]))
    return chains


# ── 5. prioritise ───────────────────────────────────────────────────────────
def priority(f):
    base = SEVERITY_WEIGHT.get(f.severity, 0)
    p = base * CONFIDENCE_FACTOR.get(f.confidence, 0.6)
    if f.category == "secret" and ("committed" in f.notes or "history" in f.notes or "browser" in f.notes):
        p += 8
    return p


def build_fix_plan(findings):
    live = [f for f in findings if f.severity in ("critical", "high", "medium")]
    ranked = sorted(live, key=lambda f: -priority(f))
    plan = []

    def refs(items):
        return ["%s %s" % (f.location(), f.rule) for f in items][:10]

    real_secrets = [f for f in ranked if f.category == "secret" and f.confidence != "low"]
    if real_secrets:
        plan.append(PlanItem(
            0, "Rotate every real secret first",
            "A key that was ever readable by someone else must be treated as stolen. Removing it from the "
            "code does not un-leak it.",
            "Revoke each one in its provider dashboard, create a new one, and load it from an environment variable.",
            refs(real_secrets)))
    git_bad = [f for f in ranked if f.category == "git"]
    if git_bad:
        plan.append(PlanItem(
            0, "Stop the .env from leaking again",
            "Git will happily publish a file you forgot to ignore.",
            "Add the .env name to .gitignore, run `git rm --cached` for tracked ones, and keep a .env.example with fake values.",
            refs(git_bad)))
    code_hi = [f for f in ranked if f.category == "code" and f.confidence == "high"]
    if code_hi:
        plan.append(PlanItem(
            0, "Fix the code paths user input can reach",
            "These risky calls sit next to input a user controls.",
            "Use the fix shown on each finding (list arguments, placeholders, safe loaders), then re-run the agent.",
            refs(code_hi)))
    code_rest = [f for f in ranked if f.category == "code" and f.confidence != "high"]
    if code_rest:
        plan.append(PlanItem(
            0, "Review the code findings that may be internal-only",
            "No user input was spotted nearby, so these are lower risk, but one refactor can change that.",
            "Trace where each value comes from. Add `# cipherbloom:ignore` only when you are sure.",
            refs(code_rest)))
    low_secrets = [f for f in ranked if f.category == "secret" and f.confidence == "low"]
    if low_secrets:
        plan.append(PlanItem(
            0, "Confirm the likely-sample secrets",
            "They look like test data or stay on your machine, but a quick look is cheap.",
            "Open each one. If it is real, rotate it; if fake, mark the line `# cipherbloom:ignore`.",
            refs(low_secrets)))
    rest = [f for f in findings if f.category not in ("secret", "git", "code") and f.severity != "info"]
    if rest:
        plan.append(PlanItem(
            0, "Tidy syntax and dependency issues",
            "Small things that break builds or let a bad version slip in.",
            "Fix the syntax errors, then pin your dependency versions.",
            refs(rest)))
    for i, item in enumerate(plan, 1):
        item.order = i
    return plan


# ── the loop ────────────────────────────────────────────────────────────────
def run_agent(root, options=None, live_target=None, deep=False, brain=None, progress=None):
    """Run the full agent. `brain` is an optional object with .review(root, result) from llm.py."""
    options = dict(options or {})
    steps, notes = [], []
    profile = profile_project(root)
    bits = []
    if profile["languages"]:
        bits.append("/".join(profile["languages"]))
    if profile["frameworks"]:
        bits.append("using " + ", ".join(profile["frameworks"]))
    steps.append(Step("profile", "%d files. %s. %s." % (
        profile["files"], " ".join(bits) or "No recognisable code",
        "Git repo" if profile["is_git"] else "Not a git repo")))
    keys, plan_steps = make_plan(profile, options, live_target)
    steps += plan_steps
    options["checks"] = keys
    findings, checks, scan_notes, secs = run_scan(root, options, live_target=live_target,
                                                  deep=deep, progress=progress)
    notes += scan_notes
    steps.append(Step("act", "Ran %s and got %d findings in %.2fs." % (", ".join(checks) or "nothing", len(findings), secs)))
    investigate(root, findings, profile, steps)
    chains = correlate(findings)
    if chains:
        steps.append(Step("correlate", "Linked findings into %d attack chain%s: %s." % (
            len(chains), "" if len(chains) == 1 else "s", ", ".join(c.id for c in chains))))
    else:
        steps.append(Step("correlate", "No findings combine into a bigger attack chain."))
    result = AgentResult(root=root, brain="built-in (offline, no AI)", profile=profile, steps=steps,
                         checks=checks, findings=findings, chains=chains, plan=[], notes=notes, seconds=secs)
    if brain is not None:
        try:
            brain.review(root, result)
            result.brain = "built-in + %s" % brain.label
            result.chains = correlate(result.findings) or result.chains
        except Exception as exc:  # the AI layer must never take the scan down
            result.notes.append("AI review stopped early (%s). Showing the built-in results." % exc)
            steps.append(Step("ai", "AI review failed: %s" % exc))
    result.findings = sort_findings(result.findings)
    result.plan = build_fix_plan(result.findings)
    steps.append(Step("prioritise", "Built a %d-step fix plan, most urgent first." % len(result.plan)))
    return result
