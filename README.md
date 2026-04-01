# env-guardian

> Protect your secrets. Audit your env vars. Never leak an API key again.

A [Claude Code](https://claude.ai/code) skill that scans your project for environment variable usage across multiple languages, checks for security vulnerabilities, validates completeness, and generates a proper `.env.example` with a type-safe config loader.

## Features

- **Multi-Language Scanning**

  | Language | Patterns Detected |
  |----------|-------------------|
  | Python | `os.environ['X']`, `os.getenv('X')`, `os.environ.get('X')` |
  | JavaScript | `process.env.X`, `process.env['X']` |
  | Ruby | `ENV['X']`, `ENV.fetch('X')` |
  | Go | `os.Getenv("X")`, `os.LookupEnv("X")` |
  | Docker | `ENV X`, `ARG X`, `${X}` |
  | CI/CD | GitHub Actions `${{ secrets.X }}`, GitLab CI variables |

- **Security Checks**
  - `.env` missing from `.gitignore` (CRITICAL)
  - Hardcoded secrets in source code (CRITICAL)
  - `.env` committed in git history (CRITICAL)
  - Sensitive variable name detection (WARNING)
  - **Never outputs actual secret values** — all values redacted

- **Completeness Analysis**
  - Variables used in code but missing from `.env.example`
  - Variables in `.env.example` but unused in code
  - Required vs optional classification

- **Auto-Generated Outputs**
  - Complete `.env.example` with categorized comments
  - Type-safe Python `Config` dataclass with typed getters

## Installation

```bash
claude skill add daizhouchen/env-guardian
```

## How It Works

1. **Scan** — `scripts/scan_env.py` finds all env var references across your codebase
2. **Audit** — `scripts/check_security.py` checks for security vulnerabilities
3. **Generate** — `scripts/generate_env_example.py` creates `.env.example` and config loader

## Manual Usage

```bash
# Scan for all env var references
python3 scripts/scan_env.py /path/to/project

# Run security audit
python3 scripts/check_security.py /path/to/project

# Generate .env.example and config loader
python3 scripts/generate_env_example.py --write
```

## Trigger Phrases

- "环境变量" / ".env" / "配置安全"
- "API key 泄露" / "secrets"
- "帮我检查一下配置有没有问题"

## Project Structure

```
env-guardian/
├── SKILL.md                        # Skill definition and workflow
├── scripts/
│   ├── scan_env.py                 # Multi-language env var scanner
│   ├── check_security.py           # Security vulnerability checker
│   └── generate_env_example.py     # .env.example and config generator
└── README.md
```

## Security Report Severities

| Severity | Finding | Example |
|----------|---------|---------|
| CRITICAL | `.env` not in `.gitignore` | Missing gitignore entry |
| CRITICAL | Hardcoded secret | `API_KEY = "sk-abc123..."` in source |
| CRITICAL | `.env` in git history | `.env` was committed previously |
| WARNING | Sensitive var in `.env` | Variable named `*_SECRET`, `*_PASSWORD` |

## Security Principles

- **Never** includes actual secret values in any output
- Values are redacted to `xx****xx` format
- Only reports variable names and metadata
- Safe to share reports with your team

## Requirements

- Python 3.8+ (no external packages)
- Git (for history analysis)

## License

MIT
