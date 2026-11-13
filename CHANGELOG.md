# Changelog

## 0.2.0 - 2026-11-13

- New `cipherbloom agent` command. Instead of running every check blindly, it profiles the project, picks the checks that make sense, runs them, then investigates each finding and returns a short list of what to fix first
- Per-finding follow-up: is the file committed or in git history, does it sit in browser-facing code, does user input reach the risky line in the same function, or is it just test/sample data. Each finding now carries a `confidence` and a plain-language `notes` field (also in the JSON report)
- Attack chains: findings that make each other worse are linked (leaked `.env`, injection plus debug mode, secrets in browser code)
- Works fully offline with no AI and no key. Optional `--ai` adds a review by your own model: a local one (Ollama and friends) or any OpenAI-compatible endpoint
- AI mode is locked down: secrets are masked before anything is sent, `.env` and key files are never readable, remote endpoints need `--allow-send-code`, the model only gets read-only tools, it can never remove or downgrade a finding, and anything it adds is labelled `ai-suggested`
- `--fail-on` in agent mode ignores AI suggestions, so CI never fails on a guess

## 0.1.0 - 2026-10-29

First public release.

- Secret detection for AWS, GitHub, Telegram, Slack, Stripe, Discord, Google and AI-provider keys, private keys, DB URLs and high-entropy hard-coded secrets, with masked output
- `.env` hygiene: not ignored, tracked by git, present in git history, missing `.env.example`
- Risky-code rules for Python and JavaScript/TypeScript
- Python, JSON and JavaScript syntax checks with line numbers
- Dependency hygiene, plus optional `pip-audit` / `npm audit`
- Consent-gated, read-only, localhost-only live check
- Scan a folder, a `.zip` or a public repo link
- Glassmorphic localhost dashboard (`cipherbloom ui`) with token and Host-header protection
- Animated HTML and JSON reports
- Git pre-commit hook and GitHub Action
