# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: jeremy@intentsolutions.io

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

You should receive a response within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Security Model

This plugin is a **prompt injection vector** — anyone who can send a message that reaches the Claude Code session can potentially manipulate Claude. The security architecture has multiple defense layers:

1. **Inbound gate**: Drops all messages from non-allowlisted senders before they reach MCP
2. **Outbound gate**: Restricts replies to channels that passed the inbound gate
3. **File exfiltration guard**: Blocks sending state directory files (`.env`, `access.json`)
4. **System prompt hardening**: Instructs Claude to refuse pairing/access manipulation from messages
5. **Token security**: All secrets are `chmod 0o600`, never logged, atomic writes

See the threat model in the project plan for the full analysis.

## Scope

In scope:
- Gate bypass (message reaches Claude from ungated sender)
- Token exfiltration (secrets sent via reply tool or leaked in tool results)
- State tampering (access.json modified by message content)
- Outbound gate bypass (reply sent to arbitrary channel)
- Bot-to-bot amplification

Out of scope:
- Slack platform vulnerabilities (report to Slack)
- Claude Code vulnerabilities (report to Anthropic)
- Social engineering of the terminal user (not a software bug)

## Chain of trust (hardened fork)

This repository is a **hardened fork** of
[jeremylongshore/claude-code-slack-channel](https://github.com/jeremylongshore/claude-code-slack-channel)
maintained for use on the operator's own developer laptop. It exists
because the upstream plugin, as of v0.2.0, had unresolved findings from a
blind security review and because the operator's laptop holds
production credentials (Redshift, Confluent, Looker, AWS, Netlify,
Google OAuth, SSH) that a prompt-injection foothold could exfiltrate.

### Installation

This plugin is **not** installed via any marketplace. It is loaded from
a local clone of this fork only, using Claude Code's development-mode
flag:

```bash
claude --dangerously-load-development-channels server:slack
```

The local clone must point at a ref on this fork's `main` branch (or
another ref whose commits have been reviewed). Do not point dev-mode
loading at an upstream tag, a marketplace cache, or any path that is
not owned by the operator.

### Updates from upstream

Upstream releases are not auto-merged. The process is:

1. Read upstream's diff against the current fork base manually.
2. Cherry-pick or re-apply only the changes that survive review.
3. Re-run the blind security critic against the resulting tree.
4. Only then update `main` on this fork.

Do not run `git pull upstream main`, do not add an upstream remote
that any automation reads, and do not let any tooling auto-accept
Renovate/Dependabot PRs from the upstream repo.

### Dependency pinning

All runtime and dev dependencies are pinned to exact versions in
`package.json`, and `bun install` is invoked with
`--frozen-lockfile` inside the `start` script. Any resolution drift
fails the boot instead of silently pulling fresh code.
