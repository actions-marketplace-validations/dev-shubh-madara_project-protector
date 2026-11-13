from __future__ import annotations

import json
import os
import sys
import time

from . import __version__
from .models import SEVERITY_ORDER, score, sort_findings

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[93m",
          "low": "\033[96m", "info": "\033[90m"}
RESET, BOLD, DIM, PINK, GREEN = "\033[0m", "\033[1m", "\033[2m", "\033[95m", "\033[92m"

BANNER = r"""
   ____ _       _               ____  _
  / ___(_)_ __ | |__   ___ _ __| __ )| | ___   ___  _ __ ___
 | |   | | '_ \| '_ \ / _ \ '__|  _ \| |/ _ \ / _ \| '_ ` _ \
 | |___| | |_) | | | |  __/ |  | |_) | | (_) | (_) | | | | | |
  \____|_| .__/|_| |_|\___|_|  |____/|_|\___/ \___/|_| |_| |_|
         |_|         G U A R D I A N   -   no AI, no API key
"""


def use_color(force_off=False):
    return not force_off and sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def summary_counts(findings):
    counts = dict((k, 0) for k in SEVERITY_ORDER)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def print_terminal(findings, target, checks, color=True, quiet=False):
    c = (lambda s, code: "%s%s%s" % (code, s, RESET)) if color else (lambda s, code: s)
    findings = sort_findings(findings)
    if not quiet:
        print(c(BANNER, PINK))
    print(c("Scanning: ", BOLD) + target)
    print(c("Checks  : ", BOLD) + ", ".join(checks) + "\n")
    if not findings:
        print(c("No issues found by the checks above.", GREEN))
        print(c("(That means these checks passed - not a guarantee that nothing is wrong.)", DIM))
    for i, f in enumerate(findings, 1):
        tag = c(" %s " % f.severity.upper(), COLORS.get(f.severity, ""))
        print("%s %s  %s" % (tag, c(f.title, BOLD), c(f.location(), DIM)))
        if f.snippet:
            print("     found : %s" % f.snippet)
        if f.why:
            print("     why   : %s" % f.why)
        if f.fix:
            print("     fix   : %s" % f.fix)
        print()
    counts = summary_counts(findings)
    line = "  ".join("%s %d" % (k, counts[k]) for k in SEVERITY_ORDER)
    print(c("Summary: ", BOLD) + line)
    print(c("Health score: ", BOLD) + "%d/100  %s" % (
        score(findings), c("(a heuristic, not a promise of safety)", DIM)))


def to_dict(findings, target, checks):
    findings = sort_findings(findings)
    return {
        "tool": "CipherBloom Guardian", "version": __version__,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "target": target,
        "checks": checks, "score": score(findings), "counts": summary_counts(findings),
        "findings": [f.to_dict() for f in findings],
        "disclaimer": "Passing these checks does not guarantee a project is secure.",
    }


def write_json(path, findings, target, checks):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(findings, target, checks), fh, indent=2)


CONF_LABEL = {"high": "sure", "medium": "likely", "low": "maybe", "ai-suggested": "AI idea", "": ""}


def print_agent(result, target, color=True, quiet=False):
    c = (lambda s, code: "%s%s%s" % (code, s, RESET)) if color else (lambda s, code: s)
    if not quiet:
        print(c(BANNER, PINK))
    print(c("Agent   : ", BOLD) + target)
    print(c("Brain   : ", BOLD) + result.brain + "\n")
    print(c("What the agent did", BOLD))
    for s in result.steps:
        print("  %-11s %s" % (s.phase, s.text))
    print()
    if result.chains:
        print(c("Attack chains", BOLD))
        for ch in result.chains:
            print(c("  ! %s" % ch.title, COLORS["high"]))
            print("    %s" % ch.why)
            for ref in ch.findings[:4]:
                print(c("      - %s" % ref, DIM))
        print()
    if result.plan:
        print(c("Fix these first, in this order", BOLD))
        for item in result.plan:
            print(c("  %d. %s" % (item.order, item.title), GREEN))
            print("     why : %s" % item.why)
            print("     how : %s" % item.how)
            for ref in item.refs[:5]:
                print(c("           %s" % ref, DIM))
            if len(item.refs) > 5:
                print(c("           ...and %d more" % (len(item.refs) - 5), DIM))
        print()
    elif not result.findings:
        print(c("Nothing found by the checks the agent chose.", GREEN))
        print(c("(That means these checks passed - not a guarantee that nothing is wrong.)", DIM))
    print(c("All findings", BOLD))
    for f in result.findings:
        tag = c(" %s " % f.severity.upper(), COLORS.get(f.severity, ""))
        conf = CONF_LABEL.get(f.confidence, f.confidence)
        print("%s %s  %s  %s" % (tag, c(f.title, BOLD), c(f.location(), DIM), c("[%s]" % conf if conf else "", DIM)))
        if f.snippet:
            print("     found : %s" % f.snippet)
        if f.notes:
            print("     agent : %s" % f.notes)
        if f.fix:
            print("     fix   : %s" % f.fix)
        print()
    for note in result.notes:
        print("Note:", note)
    counts = summary_counts(result.findings)
    print(c("Summary: ", BOLD) + "  ".join("%s %d" % (k, counts[k]) for k in SEVERITY_ORDER))
    print(c("Health score: ", BOLD) + "%d/100  %s" % (
        score(result.findings), c("(a heuristic, not a promise of safety)", DIM)))


def write_agent_json(path, result, target):
    data = to_dict(result.findings, target, result.checks)
    data["agent"] = result.to_dict()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
