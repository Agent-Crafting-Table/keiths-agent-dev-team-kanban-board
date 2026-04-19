# Kanban Board

A self-hosted kanban board server for the [autonomous dev agents system](https://github.com/Agent-Crafting-Table/autonomous-dev-agents-system). Connects to your backlog (`backlog.md`), shows agent status with live countdowns, displays VPS health metrics, tracks your CI queue, and lets you manage proposals — all in one browser tab.

**Access is protected by TOTP (Google Authenticator). No passwords, no accounts.**

---

## Features

- **Kanban board** — live view of your backlog columns (Ready → In Progress → In Review → Approved → Shipped), with drag-to-move and reorder controls
- **Agent panel** — live countdown to next fire for every agent; running/paused/stuck status; click ▶ to trigger a manual run
- **VPS health bar** — CPU, RAM, swap, disk, GitHub Actions runner status, all updated every 10s
- **CI queue** — in-progress and queued CI runs; bump a run to front (cancels others), cancel, or retry
- **Proposals panel** — view, accept, reject, or ask about proposals surfaced by your agents; accept/reject posts to Discord
- **WebSocket push** — board updates the moment `backlog.md` or `proposals.md` changes on disk
- **Pause/unpause** — kill switch for the whole agent system from the UI

---

## Requirements

- Node.js 18+
- [autonomous-dev-agents-system](https://github.com/Agent-Crafting-Table/autonomous-dev-agents-system) running in the same workspace
- `gh` CLI authenticated on the server (for CI queue and runner status)
- Google Authenticator (or any TOTP app) on your phone

---

## Setup

### 1. Install

```bash
npm install
```

### 2. Configure paths

The server reads three environment variables. Set them in your startup script or systemd unit:

| Variable | Default | Description |
|---|---|---|
| `BACKLOG_PATH` | `../<your-project>/research/agents/backlog.md` | Absolute path to your backlog file |
| `AGENTS_DIR` | `../<your-project>/research/agents` | Directory containing lock files and agent-log.md |
| `PROPOSALS_CHANNEL_ID` | `YOUR_PROPOSALS_CHANNEL_ID` | Discord channel ID for proposal notifications |
| `GH_PATH` | `gh` | Path to the `gh` CLI binary if not on PATH |

Edit the `AGENT_DEFS` array at the top of `server.js` to match your project's agent IDs and schedules (these match your `crons/jobs.json`).

### 3. Start

```bash
node server.js
```

The server listens on port `4242`. First time you visit, you'll be walked through adding it to Google Authenticator. After that, every visit requires a TOTP code.

### 4. Access remotely via SSH tunnel

On your local machine:

```bash
ssh -L 4242:localhost:4242 user@your-vps
```

Then open `http://localhost:4242` in your browser.

### 5. Run persistently

```bash
# In a tmux session (simple)
tmux new-session -d -s kanban 'node /path/to/server.js'

# Or as a systemd service (recommended for production)
```

---

## Security notes

- `totp_secret.txt` and `totp_configured.txt` are gitignored — never commit them
- The server binds to `0.0.0.0:4242` — use a firewall or SSH tunnel; don't expose it publicly without a reverse proxy and TLS
- Session tokens live in memory only; restarting the server invalidates all sessions

---

## Customizing columns

The `COLUMN_ORDER` array in `server.js` controls which columns appear and in what order. Default:

```js
const COLUMN_ORDER = [
  'Ready', 'In Progress', 'In Review', 'Changes Requested',
  'Pending Human', 'Approved', "Owner's Queue", 'Shipped',
];
```

Update this to match the `## Heading` names used in your `backlog.md`.

---

Part of the [Agent-Crafting-Table](https://github.com/Agent-Crafting-Table) toolkit. See [autonomous-dev-agents-system](https://github.com/Agent-Crafting-Table/autonomous-dev-agents-system) for the full agent loop.
