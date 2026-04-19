#!/usr/bin/env node
'use strict';

const http = require('http');
const fs   = require('fs');
const path = require('path');
const os = require('os');
const { spawn, exec } = require('child_process');
const { WebSocketServer } = require('ws');

const WORKSPACE    = path.join(__dirname, '..');
const BACKLOG_PATH = process.env.BACKLOG_PATH || path.join(__dirname, '../[your-project]/research/agents/backlog.md');
const AGENTS_DIR   = process.env.AGENTS_DIR || path.join(__dirname, '../[your-project]/research/agents');
const JOBS_FILE    = path.join(WORKSPACE, 'crons/jobs.json');
const LOG_DIR      = path.join(WORKSPACE, 'crons/logs');
const AGENT_LOG    = path.join(AGENTS_DIR, 'agent-log.md');
const PROPOSALS_PATH = path.join(AGENTS_DIR, 'proposals.md');

// ---------------------------------------------------------------------------
// TOTP Auth
// ---------------------------------------------------------------------------

const crypto = require('crypto');

const SECRET_FILE    = path.join(__dirname, 'totp_secret.txt');
const CONFIGURED_FILE = path.join(__dirname, 'totp_configured.txt');

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(str) {
  str = str.replace(/=+$/, '').toUpperCase();
  let bits = 0, value = 0;
  const output = [];
  for (const c of str) {
    const idx = BASE32.indexOf(c);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(output);
}

function generateSecret() {
  const bytes = crypto.randomBytes(20);
  let result = '', bits = 0, value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { result += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) result += BASE32[(value << (5 - bits)) & 31];
  return result;
}

function totpCode(secret, windowOffset = 0) {
  const key  = base32Decode(secret);
  const step = BigInt(Math.floor(Date.now() / 1000 / 30) + windowOffset);
  const buf  = Buffer.alloc(8);
  buf.writeBigUInt64BE(step);
  const hmac   = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code   = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset+1] & 0xff) << 16) |
                 ((hmac[offset+2] & 0xff) << 8)  |  (hmac[offset+3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}

function verifyTOTP(secret, token) {
  return [-1, 0, 1].some(w => totpCode(secret, w) === String(token).trim());
}

// Load or create secret
let TOTP_SECRET;
try { TOTP_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim(); }
catch (_) {
  TOTP_SECRET = generateSecret();
  fs.writeFileSync(SECRET_FILE, TOTP_SECRET);
  console.log(`\n  TOTP secret generated and saved to ${SECRET_FILE}`);
}

function isConfigured() { return fs.existsSync(CONFIGURED_FILE); }
function markConfigured() { fs.writeFileSync(CONFIGURED_FILE, '1'); }

function otpauthUrl() {
  return `otpauth://totp/Agent%20Kanban?secret=${TOTP_SECRET}&issuer=AgentKanban&algorithm=SHA1&digits=6&period=30`;
}

const sessions = new Set();

function makeToken() {
  return [...Array(32)].map(() => Math.floor(Math.random() * 36).toString(36)).join('');
}

function validToken(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  return token && sessions.has(token);
}

function validWsToken(url) {
  const m = (url || '').match(/[?&]token=([^&]+)/);
  return m && sessions.has(decodeURIComponent(m[1]));
}

const PORT = 4242;

// ---------------------------------------------------------------------------
// Backlog parser
// ---------------------------------------------------------------------------

const COLUMN_ORDER = [
  'Ready', 'In Progress', 'In Review', 'Changes Requested',
  'Pending Human', 'Approved', "Owner's Queue", 'Shipped',
];

function parseBacklog(content) {
  const columns = {};
  for (const col of COLUMN_ORDER) columns[col] = [];
  const parts = content.split(/^## /m);
  for (const part of parts) {
    const lines = part.split('\n');
    const heading = lines[0].trim();
    const col = COLUMN_ORDER.find(c => c.toLowerCase() === heading.toLowerCase());
    if (!col) continue;
    const taskBlocks = lines.slice(1).join('\n').split(/^### /m).slice(1);
    for (const block of taskBlocks) {
      const blockLines = block.split('\n');
      const idMatch = blockLines[0].trim().match(/^((?:TASK|BUG|AUDIT)-\d+):\s*(.+)$/);
      if (!idMatch) continue;
      const [, id, title] = idMatch;
      const body = blockLines.slice(1).join('\n');
      const f = (name) => { const m = body.match(new RegExp(`\\*\\*${name}:\\*\\*\\s*(.+)`)); return m ? m[1].trim() : null; };
      columns[col].push({ id, title, type: id.startsWith('BUG') ? 'bug' : id.startsWith('AUDIT') ? 'audit' : 'task',
        pr: f('PR'), branch: f('Branch'), priority: f('Priority') });
    }
  }
  return { columns };
}

function readBoard() {
  try { return parseBacklog(fs.readFileSync(BACKLOG_PATH, 'utf8')); }
  catch (e) { return { columns: {}, error: e.message }; }
}

// ---------------------------------------------------------------------------
// Agent status
// ---------------------------------------------------------------------------

const AGENT_DEFS = [
  { id: '[your-project]-agent-developer',        name: 'Developer',       logRole: 'DEVELOPER',       color: '#22d3ee', schedule: [0,10,20,30,40,50],              lockFile: 'DEV_LOCK',             lockMaxMs: 25*60*1000, pauseFile: 'DEV_PAUSE' },
  { id: '[your-project]-agent-reviewer',         name: 'Reviewer',        logRole: 'REVIEWER',        color: '#c084fc', schedule: [5,15,25,35,45,55],              lockFile: 'REVIEWER_LOCK',        lockMaxMs: 20*60*1000, pauseFile: 'REV_PAUSE' },
  { id: '[your-project]-agent-trd-watcher',      name: 'TRD Watcher',     logRole: 'TRD-WATCHER',     color: '#f0abfc', schedule: [2,7,12,17,22,27,32,37,42,47,52,57], lockFile: 'TRD_WATCHER_LOCK',  lockMaxMs:  7*60*1000, pauseFile: 'TRD_PAUSE' },
  { id: '[your-project]-agent-merge-watcher',    name: 'Merge Watcher',   logRole: 'MERGE-WATCHER',   color: '#60a5fa', schedule: [0,5,10,15,20,25,30,35,40,45,50,55], lockFile: 'MERGE_WATCHER_LOCK', lockMaxMs:  8*60*1000, pauseFile: 'MW_PAUSE' },
  { id: '[your-project]-agent-project-manager',  name: 'Project Mgr',     logRole: 'PROJECT-MANAGER', color: '#fbbf24', schedule: [2,32],                           lockFile: 'PM_LOCK',              lockMaxMs: 12*60*1000 },
  { id: '[your-project]-agent-product-manager',  name: 'Product Mgr',     logRole: 'PRODUCT-MANAGER', color: '#4ade80', everyNHours: 4,                            lockFile: 'PRODUCT_MANAGER_LOCK', lockMaxMs: 12*60*1000 },
  { id: '[your-project]-agent-domain-researcher', name: 'Vet Researcher', logRole: 'VET-RESEARCHER', color: '#38bdf8', daily: { hour: 7 },                  lockFile: 'VET_RESEARCHER_LOCK',  lockMaxMs: 15*60*1000 },
  { id: '[your-project]-agent-system-reviewer',  name: 'System Reviewer', logRole: 'SYSTEM-REVIEWER', color: '#fde68a', daily: { hour: 21 },                      lockFile: 'SYSTEM_REVIEWER_LOCK', lockMaxMs: 15*60*1000 },
  { id: '[your-project]-agent-codebase-auditor', name: 'Code Auditor',    logRole: 'CODEBASE-AUDITOR', color: '#fb923c', everyNHours: 3,                            lockFile: 'AUDITOR_LOCK',         lockMaxMs: 25*60*1000, pauseFile: 'AUDITOR_PAUSE' },
  { id: '[your-project]-main-ci-fixer',          name: 'Main CI Fixer',   logRole: null,               color: '#f87171', everyNMinutes: 2 },
  { id: '[your-project]-pr-ci-fixer',            name: 'PR CI Fixer',     logRole: null,               color: '#fdba74', everyNMinutes: 2,                            lockFile: '/tmp/[your-project]-pr-ci-fixer.lock', lockMaxMs: 20*60*1000 },
];

function fileExists(p) { try { fs.statSync(p); return true; } catch { return false; } }
function fileMtimeMs(p) { try { return fs.statSync(p).mtimeMs; } catch { return 0; } }
function isPaused() { return fileExists(path.join(AGENTS_DIR, 'PAUSE')); }

function secsUntilNextMinute(minutes) {
  const now = new Date();
  const secsIntoHour = now.getMinutes() * 60 + now.getSeconds();
  let best = Infinity;
  for (const min of minutes) {
    let diff = min * 60 - secsIntoHour;
    if (diff <= 0) diff += 3600;
    if (diff < best) best = diff;
  }
  return best;
}

function secsUntilEveryNHours(n) {
  const now = new Date();
  const secsIntoDay = now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds();
  const interval = n * 3600;
  const diff = interval - (secsIntoDay % interval);
  return diff === interval ? 0 : diff;
}

function secsUntilEveryNMinutes(n) {
  const now = new Date();
  const secsIntoHour = now.getMinutes() * 60 + now.getSeconds();
  const interval = n * 60;
  const diff = interval - (secsIntoHour % interval);
  return diff === interval ? 0 : diff;
}

function secsUntilDaily(hour) {
  const now = new Date();
  const et = new Date(now.toLocaleString('en-US', { timeZone: 'America/New_York' }));
  const secsIntoDay = et.getHours() * 3600 + et.getMinutes() * 60 + et.getSeconds();
  const target = hour * 3600;
  let diff = target - secsIntoDay;
  if (diff <= 0) diff += 86400;
  return diff;
}

function getSecsUntilNext(def) {
  if (def.daily)         return secsUntilDaily(def.daily.hour);
  if (def.everyNHours)   return secsUntilEveryNHours(def.everyNHours);
  if (def.everyNMinutes) return secsUntilEveryNMinutes(def.everyNMinutes);
  return secsUntilNextMinute(def.schedule);
}

function getMaxIntervalSecs(def) {
  if (def.daily)         return 86400;
  if (def.everyNHours)   return def.everyNHours * 3600;
  if (def.everyNMinutes) return def.everyNMinutes * 60;
  // time between consecutive scheduled minutes
  const sorted = [...def.schedule].sort((a, b) => a - b);
  let maxGap = 0;
  for (let i = 1; i < sorted.length; i++) maxGap = Math.max(maxGap, sorted[i] - sorted[i-1]);
  // wrap-around gap
  maxGap = Math.max(maxGap, 60 - sorted[sorted.length - 1] + sorted[0]);
  return maxGap * 60;
}

// Reads last 16KB of agent-log.md and extracts last "next:" hint for a role
function lastNextHint(logRole) {
  if (!logRole) return '';
  try {
    const size = fs.statSync(AGENT_LOG).size;
    const readSize = Math.min(16384, size);
    const buf = Buffer.alloc(readSize);
    const fd  = fs.openSync(AGENT_LOG, 'r');
    fs.readSync(fd, buf, 0, readSize, Math.max(0, size - readSize));
    fs.closeSync(fd);
    const text   = buf.toString('utf8');
    const blocks = text.split(/^## /m);
    const headerRe = new RegExp(`^[\\d-]+ [\\d:]+ (?:ET )?${logRole}\\s*$`, 'im');
    let lastNext = '';
    for (const block of blocks) {
      if (!headerRe.test(block.split('\n')[0])) continue;
      const m = block.match(/^- next:\s*(.+)$/m);
      if (m) lastNext = m[1].trim();
    }
    return lastNext.length > 60 ? lastNext.slice(0, 58) + '…' : lastNext;
  } catch { return ''; }
}

function buildAgentStatus() {
  const globalPaused = isPaused();
  return AGENT_DEFS.map(def => {
    const lockPath  = def.lockFile  ? (def.lockFile.startsWith('/') ? def.lockFile : path.join(AGENTS_DIR, def.lockFile))  : null;
    const pausePath = def.pauseFile ? path.join(AGENTS_DIR, def.pauseFile) : null;
    const lockAge   = lockPath ? (Date.now() - fileMtimeMs(lockPath)) : Infinity;
    const locked    = lockPath ? fileExists(lockPath) : false;
    const agentPaused = globalPaused || (pausePath ? fileExists(pausePath) : false);

    let status = 'idle';
    if (locked && lockAge < def.lockMaxMs)     status = 'running';
    else if (locked && lockAge >= def.lockMaxMs) status = 'stuck';
    else if (agentPaused)                        status = 'paused';

    // If being manually triggered via kanban, override to 'running'
    if (runningAgents.has(def.id)) status = 'running';

    const secsUntil = getSecsUntilNext(def);
    const maxSecs   = getMaxIntervalSecs(def);
    const hint      = lastNextHint(def.logRole);

    return { id: def.id, name: def.name, color: def.color, status, secsUntil, maxSecs, hint };
  });
}

// ---------------------------------------------------------------------------
// VPS health + CI queue cache
// ---------------------------------------------------------------------------

let vpsCache = { mem: null, cpu: null, swap: null, disk: null, uptime: 0, ts: 0 };
let ciCache  = { runners: [], queue: [], bumpCancelled: [], ts: 0 };

function refreshVps() {
  const total  = os.totalmem();
  const free   = os.freemem();
  const load   = os.loadavg()[0];
  const cores  = os.cpus().length;
  const uptime = os.uptime();
  let pending = 2, swapTotal = 0, swapUsed = 0, diskTotal = 0, diskUsed = 0;

  const done = () => {
    if (--pending > 0) return;
    vpsCache = {
      mem:   { total, used: total - free },
      cpu:   { load1: load, cores },
      swap:  { total: swapTotal, used: swapUsed },
      disk:  { total: diskTotal, used: diskUsed },
      uptime, ts: Date.now(),
    };
  };

  exec("awk '/^SwapTotal/{t=$2} /^SwapFree/{f=$2} END{print t+0, f+0}' /proc/meminfo",
    (err, stdout) => {
      if (!err && stdout) {
        const [t, f] = stdout.trim().split(' ').map(Number);
        swapTotal = t * 1024;
        swapUsed  = (t - f) * 1024;
      }
      done();
    });

  exec("df -B1 / | awk 'NR==2{print $2, $3}'",
    (err, stdout) => {
      if (!err && stdout) {
        const [t, u] = stdout.trim().split(' ').map(Number);
        diskTotal = t || 0;
        diskUsed  = u || 0;
      }
      done();
    });
}

const GH = process.env.GH_PATH || 'gh';

function ghApi(endpoint, cb) {
  exec(`${GH} api "${endpoint}"`,
    { env: { ...process.env, HOME: process.env.HOME || require('os').homedir() } },
    (err, stdout) => {
      if (err || !stdout) return cb(null);
      try { cb(JSON.parse(stdout.trim())); } catch (_) { cb(null); }
    });
}

function mapRun(r) {
  return {
    id: r.id,
    branch: r.head_branch,
    status: r.status,
    url: r.html_url,
    prs: (r.pull_requests || []).map(p => ({ number: p.number })),
    created_at: r.created_at,
  };
}

function refreshCi() {
  let pending = 3, runners = [], inProgress = [], queued = [];
  const done = () => {
    if (--pending > 0) return;
    const queue = [...inProgress, ...queued];
    const activeIds = new Set(queue.map(r => r.id));
    ciCache.bumpCancelled = ciCache.bumpCancelled.filter(r => !activeIds.has(r.id));
    ciCache.runners = runners;
    ciCache.queue   = queue;
    ciCache.ts      = Date.now();
    broadcastState();
  };

  ghApi('repos/YOUR_GITHUB_ORG/YOUR_REPO/actions/runners', (data) => {
    if (data && data.runners) {
      runners = data.runners.map(r => ({ id: r.id, name: r.name, status: r.status, busy: r.busy }));
    }
    done();
  });

  ghApi('repos/YOUR_GITHUB_ORG/YOUR_REPO/actions/runs?status=in_progress&per_page=50', (data) => {
    if (data && data.workflow_runs) inProgress = data.workflow_runs.map(mapRun);
    done();
  });

  ghApi('repos/YOUR_GITHUB_ORG/YOUR_REPO/actions/runs?status=queued&per_page=50', (data) => {
    if (data && data.workflow_runs) queued = data.workflow_runs.map(mapRun);
    done();
  });
}

function loadJobs() {
  try { return JSON.parse(fs.readFileSync(JOBS_FILE, 'utf8')).jobs || []; }
  catch (e) { return []; }
}

// ---------------------------------------------------------------------------
// Proposals parser
// ---------------------------------------------------------------------------

function parseProposals() {
  let content;
  try { content = fs.readFileSync(PROPOSALS_PATH, 'utf8'); }
  catch (_) { return []; }

  const proposals = [];
  const parts = content.split(/(?=^## |^### )/m);

  for (const part of parts) {
    const firstLine = part.split('\n')[0];

    // Standard proposal: ## YYYY-MM-DD ROLE — title
    const stdMatch = firstLine.match(/^## (\d{4}-\d{2}-\d{2}) (.+?) — (.+)$/);
    if (stdMatch) {
      const [, date, role, title] = stdMatch;
      const body = part.slice(firstLine.length).trim();
      const f = (field) => {
        const m = body.match(new RegExp(`\\*\\*${field}:\\*\\*\\s*([\\s\\S]+?)(?=\\n\\*\\*[A-Z]|$)`));
        return m ? m[1].trim() : '';
      };
      proposals.push({ type: 'proposal', date, role, title,
        context: f('Context'), proposal: f('Proposal'),
        why: f('Why it matters'), tradeoff: f('Tradeoff'),
        headerLine: firstLine, raw: part });
      continue;
    }

    // System improvement: ### System Improvement: title (from Role, YYYY-MM-DD)
    const sysMatch = firstLine.match(/^### System Improvement: (.+?) \(from (.+?), (\d{4}-\d{2}-\d{2})\)/);
    if (sysMatch) {
      const [, title, role, date] = sysMatch;
      const body = part.slice(firstLine.length).trim();
      const impactMatch = body.match(/\*\*Impact:\*\*\s*(\w+)/);
      const effortMatch = body.match(/\*\*Effort:\*\*\s*(\w+)/);
      proposals.push({ type: 'system', date, role, title,
        impact: impactMatch ? impactMatch[1] : '',
        effort: effortMatch ? effortMatch[1] : '',
        body: body,
        headerLine: firstLine, raw: part });
      continue;
    }
  }

  return proposals;
}

// ---------------------------------------------------------------------------
// Card mover
// ---------------------------------------------------------------------------

function moveCard(cardId, targetColumn) {
  let content;
  try { content = fs.readFileSync(BACKLOG_PATH, 'utf8'); }
  catch (_) { return false; }

  const targetHeading = COLUMN_ORDER.find(c => c.toLowerCase() === targetColumn.toLowerCase());
  if (!targetHeading) return false;

  const eid = cardId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Capture the card block: from \n### ID: up to next \n### or \n## or end of string
  const cardRe = new RegExp(`(\\n### ${eid}:[\\s\\S]+?)(?=\\n### |\\n## |$)`);
  const match = content.match(cardRe);
  if (!match) return false;

  const cardBlock = match[1]; // starts with \n

  // Remove the card from its current position
  let updated = content.replace(cardBlock, '');

  // Insert at top of target section (right after ## Heading line)
  const sectionRe = new RegExp(
    `(^## ${targetHeading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[ \\t]*\\n)`, 'm');
  if (!sectionRe.test(updated)) return false;

  updated = updated.replace(sectionRe, `$1${cardBlock.replace(/^\n/, '')}\n`);
  updated = updated.replace(/\n{4,}/g, '\n\n\n');

  fs.writeFileSync(BACKLOG_PATH, updated);
  return true;
}

function reorderCard(cardId, direction) {
  let content;
  try { content = fs.readFileSync(BACKLOG_PATH, 'utf8'); }
  catch (_) { return false; }

  // Split into alternating [pre-heading, heading, body, heading, body, ...]
  const parts = content.split(/^(## .+)$/m);
  let sectionBodyIdx = -1;
  for (let i = 1; i < parts.length; i += 2) {
    const heading = parts[i].replace(/^## /, '').trim();
    const col = COLUMN_ORDER.find(c => c.toLowerCase() === heading.toLowerCase());
    if (col && parts[i + 1] && parts[i + 1].includes(`### ${cardId}:`)) {
      sectionBodyIdx = i + 1;
      break;
    }
  }
  if (sectionBodyIdx === -1) return false;

  const body = parts[sectionBodyIdx];
  const segments = body.split('\n### ');
  // segments[0] = pre-card text (newlines etc.), segments[1..] = card blocks (no leading \n### )
  if (segments.length < 2) return false;

  const pre = segments[0];
  const cards = segments.slice(1);
  const cardIdx = cards.findIndex(b => b.startsWith(cardId + ':'));
  if (cardIdx === -1) return false;

  let newIdx;
  if (direction === 'up')     newIdx = cardIdx - 1;
  else if (direction === 'down')   newIdx = cardIdx + 1;
  else if (direction === 'top')    newIdx = 0;
  else if (direction === 'bottom') newIdx = cards.length - 1;
  else return false;

  if (newIdx < 0 || newIdx >= cards.length || newIdx === cardIdx) return false;

  const [card] = cards.splice(cardIdx, 1);
  cards.splice(newIdx, 0, card);

  parts[sectionBodyIdx] = pre + '\n### ' + cards.join('\n### ');
  const updated = parts.join('').replace(/\n{4,}/g, '\n\n\n');
  fs.writeFileSync(BACKLOG_PATH, updated);
  return true;
}

function removeProposal(headerLine) {
  let content;
  try { content = fs.readFileSync(PROPOSALS_PATH, 'utf8'); }
  catch (_) { return false; }

  const parts = content.split(/(?=^## |^### )/m);
  const idx = parts.findIndex(p => p.split('\n')[0] === headerLine);
  if (idx === -1) return false;

  parts.splice(idx, 1);
  let newContent = parts.join('');
  newContent = newContent.replace(/\n{3,}/g, '\n\n');
  fs.writeFileSync(PROPOSALS_PATH, newContent);
  return true;
}

// ---------------------------------------------------------------------------
// Running agents (manually triggered)
// ---------------------------------------------------------------------------

const runningAgents = new Map();

function broadcastState() {
  const board = readBoard();
  const agents = buildAgentStatus();
  const proposalsCount = parseProposals().length;
  const msg = JSON.stringify({ ...board, agents, paused: isPaused(), proposalsCount, vps: vpsCache, ci: ciCache, ts: Date.now() });
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(msg);
  }
}

function triggerAgent(jobId, res) {
  const jobs = loadJobs();
  const job  = jobs.find(j => j.id === jobId);
  if (!job)                     { res.writeHead(404); res.end('Job not found'); return; }
  if (runningAgents.has(jobId)) { res.writeHead(409); res.end('Already running'); return; }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, job: job.name }));

  runningAgents.set(jobId, true);
  broadcastState();

  fs.mkdirSync(LOG_DIR, { recursive: true });
  const logPath = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}-manual-${jobId}.log`);
  const out = fs.openSync(logPath, 'a');
  fs.writeSync(out, `\n=== ${new Date().toISOString()} — ${job.name} (manual) ===\n`);

  const child = spawn('claude',
    ['--dangerously-skip-permissions', '--model', job.model || 'sonnet', '-p', job.message],
    { cwd: WORKSPACE, stdio: ['ignore', out, out],
      env: { ...process.env, HOME: process.env.HOME || require('os').homedir() } });

  const timer = setTimeout(() => { child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 5000); },
    (job.timeoutSeconds || 300) * 1000);

  const cleanup = () => {
    clearTimeout(timer);
    try { fs.closeSync(out); } catch (_) {}
    runningAgents.delete(jobId);
    broadcastState();
  };
  child.on('close', cleanup);
  child.on('error', cleanup);
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Kanban</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #0f1117; color: #e2e8f0;
  height: 100vh; display: flex; flex-direction: column;
}

/* Auth screen */
#auth-screen {
  position: fixed; inset: 0; background: #0f1117;
  display: flex; align-items: center; justify-content: center;
  z-index: 999;
}
#auth-screen.hidden { display: none; }
.auth-box {
  background: #1a1d27; border: 1px solid #2d3148;
  border-radius: 12px; padding: 32px 28px; width: 320px;
  display: flex; flex-direction: column; gap: 14px;
}
.auth-box h2 { font-size: 15px; font-weight: 600; color: #a78bfa; text-align: center; }
.auth-box p  { font-size: 12px; color: #64748b; text-align: center; margin-top: -6px; line-height: 1.5; }
.auth-box .step { font-size: 11px; color: #94a3b8; }
.auth-box .step strong { color: #e2e8f0; }
.secret-box {
  background: #0f1117; border: 1px solid #2d3148; border-radius: 6px;
  padding: 8px 12px; font-family: monospace; font-size: 13px;
  color: #a78bfa; letter-spacing: .1em; text-align: center;
  user-select: all; word-break: break-all;
}
#code-input {
  background: #0f1117; border: 1px solid #2d3148;
  border-radius: 7px; padding: 10px 14px;
  font-size: 22px; color: #e2e8f0; letter-spacing: .4em;
  text-align: center; outline: none; width: 100%;
}
#code-input:focus { border-color: #4f46e5; }
#auth-submit {
  background: #4f46e5; color: #fff; border: none;
  border-radius: 7px; padding: 10px; font-size: 13px;
  font-weight: 600; cursor: pointer; transition: background .15s;
}
#auth-submit:hover { background: #4338ca; }
#auth-error, #login-error { font-size: 11px; color: #f87171; text-align: center; display: none; }
header {
  padding: 9px 14px; background: #1a1d27;
  border-bottom: 1px solid #2d3148;
  display: flex; align-items: center; gap: 10px; flex-shrink: 0; flex-wrap: wrap;
}
header h1 { font-size: 14px; font-weight: 700; color: #a78bfa; }
.spacer { flex: 1; }
#status { font-size: 11px; color: #64748b; }
#status.connected { color: #4ade80; }
#updated { font-size: 11px; color: #3d4462; }
.pause-badge {
  display: none; background: #7f1d1d; color: #fca5a5;
  font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 4px;
}
.pause-badge.visible { display: inline-block; }
.hbtn {
  border: none; border-radius: 5px; padding: 4px 10px;
  font-size: 11px; font-weight: 600; cursor: pointer; transition: opacity .15s;
}
.hbtn:disabled { opacity: .35; cursor: not-allowed; }
.hbtn-pause   { background: #dc2626; color: #fff; }
.hbtn-unpause { background: #16a34a; color: #fff; }

/* Layout */
.main { display: flex; flex: 1; overflow: hidden; }

/* Kanban board */
.board {
  display: flex; gap: 11px; padding: 12px;
  overflow-x: auto; flex: 1; align-items: flex-start;
}
.column {
  flex-shrink: 0; width: 230px; background: #1a1d27;
  border-radius: 9px; border: 1px solid #2d3148;
  display: flex; flex-direction: column;
  max-height: calc(100vh - 56px);
}
.col-header {
  padding: 8px 11px; font-size: 10px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .07em; color: #94a3b8;
  border-bottom: 1px solid #2d3148;
  display: flex; align-items: center; justify-content: space-between;
  flex-shrink: 0;
}
.col-count {
  background: #2d3148; color: #94a3b8;
  border-radius: 8px; padding: 1px 6px; font-size: 10px;
}
.col-body { padding: 6px; overflow-y: auto; display: flex; flex-direction: column; gap: 5px; }
.card {
  background: #242736; border: 1px solid #2d3148;
  border-radius: 6px; padding: 8px 9px; transition: border-color .15s;
}
.card:hover { border-color: #4f46e5; }
.card-id { font-size: 10px; font-weight: 700; letter-spacing: .04em; margin-bottom: 3px; }
.card.bug   .card-id { color: #f87171; }
.card.task  .card-id { color: #818cf8; }
.card.audit .card-id { color: #fb923c; }
.card-title { font-size: 11px; line-height: 1.4; color: #e2e8f0; margin-bottom: 4px; }
.card-meta  { font-size: 10px; color: #64748b; }
.card-meta a { color: #818cf8; text-decoration: none; }
.badge { display: inline-block; padding: 1px 5px; border-radius: 3px; font-size: 9px; font-weight: 700; margin-right: 3px; }
.badge.p0 { background: #7f1d1d; color: #fca5a5; }
.badge.p1 { background: #7c2d12; color: #fdba74; }
.badge.p2 { background: #713f12; color: #fde68a; }
.badge.bug-type { background: #450a0a; color: #fca5a5; }
.badge.audit-type { background: #431407; color: #fed7aa; }
.empty { font-size: 10px; color: #3d4462; text-align: center; padding: 12px; }
.card { cursor: pointer; }
.card.selected { border-color: #a78bfa; box-shadow: 0 0 0 2px #4f46e540; }
.card-controls { display: none; gap: 2px; margin-top: 5px; }
.card:hover .card-controls { display: flex; }
.reorder-btn { font-size: 10px; padding: 1px 5px; background: #1e293b; border: 1px solid #334155; border-radius: 3px; color: #64748b; cursor: pointer; line-height: 1.4; }
.reorder-btn:hover { background: #334155; color: #e2e8f0; }
.col-header.drop-target { cursor: pointer; color: #a78bfa; background: #1e1e35; }
.col-header.drop-target:hover { background: #252850; }

.col-ready             .col-header { border-top: 3px solid #4f46e5; border-radius: 9px 9px 0 0; }
.col-in-progress       .col-header { border-top: 3px solid #f59e0b; border-radius: 9px 9px 0 0; }
.col-in-review         .col-header { border-top: 3px solid #06b6d4; border-radius: 9px 9px 0 0; }
.col-changes-requested .col-header { border-top: 3px solid #ef4444; border-radius: 9px 9px 0 0; }
.col-pending-human     .col-header { border-top: 3px solid #ec4899; border-radius: 9px 9px 0 0; }
.col-approved          .col-header { border-top: 3px solid #4ade80; border-radius: 9px 9px 0 0; }
.col-owners-queue      .col-header { border-top: 3px solid #a78bfa; border-radius: 9px 9px 0 0; }
.col-shipped           .col-header { border-top: 3px solid #6b7280; border-radius: 9px 9px 0 0; }

/* Agent panel */
.agent-panel {
  width: 310px; flex-shrink: 0;
  background: #13151f; border-left: 1px solid #2d3148;
  display: flex; flex-direction: column;
  overflow: hidden;
}
.agent-panel-header {
  padding: 10px 14px 8px;
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .08em; color: #64748b;
  border-bottom: 1px solid #2d3148; flex-shrink: 0;
  display: flex; align-items: center; justify-content: space-between;
}
.collapse-btn {
  background: none; border: none; cursor: pointer;
  color: #475569; font-size: 14px; line-height: 1;
  padding: 0 2px; transition: color .15s;
}
.collapse-btn:hover { color: #94a3b8; }
.agent-panel.collapsed { width: 36px; }
.agent-panel.collapsed .agent-list,
.agent-panel.collapsed .agent-panel-header span { display: none; }
.agent-panel.collapsed .collapse-btn { transform: scaleX(-1); }
.agent-panel.collapsed { border-left: 1px solid #2d3148; }
.agent-panel { transition: width .2s ease; overflow: hidden; }
.agent-list { overflow-y: auto; flex: 1; padding: 6px; display: flex; flex-direction: column; gap: 3px; }

.agent-row {
  display: flex; align-items: center; gap: 8px;
  padding: 7px 9px; border-radius: 7px;
  border: 1px solid transparent; transition: border-color .15s;
}
.agent-row:hover { border-color: #2d3148; background: #1a1d27; }
.agent-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.agent-name { font-size: 11px; font-weight: 500; color: #cbd5e1; flex: 1; min-width: 0; }
.agent-status {
  font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 4px;
  white-space: nowrap;
}
.status-idle    { background: #1e293b; color: #64748b; }
.status-running { background: #052e16; color: #4ade80; animation: pulse .9s infinite; }
.status-paused  { background: #431407; color: #fbbf24; }
.status-stuck   { background: #7f1d1d; color: #fca5a5; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }

.agent-countdown { font-size: 10px; color: #475569; font-variant-numeric: tabular-nums; width: 36px; text-align: right; flex-shrink: 0; }
.agent-countdown.soon   { color: #fbbf24; }
.agent-countdown.urgent { color: #ef4444; }

.agent-bar { height: 2px; background: #1e293b; border-radius: 1px; margin: 2px 9px 1px; overflow: hidden; }
.agent-bar-fill { height: 100%; border-radius: 1px; transition: width .5s linear; }

.agent-hint { font-size: 9px; color: #3d4462; padding: 0 9px 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.run-btn {
  border: none; border-radius: 4px; padding: 3px 8px;
  font-size: 10px; font-weight: 600; cursor: pointer; flex-shrink: 0;
  background: #1e293b; color: #94a3b8; transition: background .15s;
}
.run-btn:hover:not(:disabled) { background: #334155; color: #e2e8f0; }
.run-btn:disabled { opacity: .3; cursor: not-allowed; }

/* Proposals panel */
#proposals-panel {
  position: fixed; inset: 0; z-index: 500;
  display: flex; align-items: stretch; justify-content: flex-end;
  background: rgba(0,0,0,.55);
}
#proposals-panel.hidden { display: none; }
.proposals-inner {
  width: min(680px, 100vw); background: #1a1d27;
  border-left: 1px solid #2d3148;
  display: flex; flex-direction: column; overflow: hidden;
}
.proposals-toolbar {
  padding: 12px 16px; border-bottom: 1px solid #2d3148;
  display: flex; align-items: center; gap: 10px; flex-shrink: 0;
}
.proposals-toolbar h2 { font-size: 14px; font-weight: 700; color: #a78bfa; flex: 1; }
.proposals-toolbar .close-btn {
  background: none; border: none; color: #64748b; font-size: 18px;
  cursor: pointer; padding: 0 4px; line-height: 1;
}
.proposals-toolbar .close-btn:hover { color: #e2e8f0; }
.proposals-list { overflow-y: auto; flex: 1; padding: 12px; display: flex; flex-direction: column; gap: 10px; }
.prop-card {
  background: #242736; border: 1px solid #2d3148;
  border-radius: 8px; padding: 12px 14px; transition: opacity .3s;
}
.prop-card-header { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px; }
.prop-type {
  font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 3px;
  flex-shrink: 0; margin-top: 2px;
}
.prop-type.proposal { background: #1e3a5f; color: #60a5fa; }
.prop-type.system   { background: #1e3a2f; color: #4ade80; }
.prop-meta { flex: 1; }
.prop-title { font-size: 12px; font-weight: 600; color: #e2e8f0; line-height: 1.4; }
.prop-sub   { font-size: 10px; color: #64748b; margin-top: 2px; }
.prop-body  { font-size: 11px; color: #94a3b8; line-height: 1.6; }
.prop-field { margin-bottom: 6px; }
.prop-field-label { font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; color: #64748b; margin-bottom: 2px; }
.prop-field-value { font-size: 11px; color: #94a3b8; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }
.prop-badges { display: flex; gap: 6px; margin-bottom: 8px; }
.prop-badge { font-size: 9px; font-weight: 700; padding: 2px 7px; border-radius: 3px; }
.impact-high   { background: #7f1d1d; color: #fca5a5; }
.impact-medium { background: #7c2d12; color: #fdba74; }
.impact-low    { background: #1e3a2f; color: #4ade80; }
.effort-high   { background: #1e1e5f; color: #818cf8; }
.effort-medium { background: #172554; color: #93c5fd; }
.effort-low    { background: #1a1d27; color: #64748b; border: 1px solid #2d3148; }
.prop-actions { display: flex; gap: 8px; margin-top: 10px; }
.prop-btn {
  border: none; border-radius: 5px; padding: 5px 14px;
  font-size: 11px; font-weight: 600; cursor: pointer; transition: opacity .15s;
}
.prop-btn:disabled { opacity: .35; cursor: not-allowed; }
.prop-btn-accept { background: #14532d; color: #4ade80; }
.prop-btn-accept:hover:not(:disabled) { background: #166534; }
.prop-btn-reject { background: #450a0a; color: #f87171; }
.prop-btn-reject:hover:not(:disabled) { background: #7f1d1d; }
.prop-btn-ask { background: #1e293b; color: #94a3b8; }
.prop-btn-ask:hover:not(:disabled) { background: #334155; color: #e2e8f0; }
#proposals-count {
  background: #4f46e5; border-radius: 9px; padding: 1px 6px;
  font-size: 10px; font-weight: 700; margin-left: 3px;
}

/* Health bar */
#health-bar {
  display: flex; align-items: center;
  padding: 3px 14px; background: #0d0f18;
  border-bottom: 1px solid #2d3148;
  flex-shrink: 0; overflow-x: auto; gap: 0;
  font-size: 11px; color: #64748b;
}
.health-item { white-space: nowrap; padding: 0 10px; line-height: 20px; }
.health-item strong { color: #e2e8f0; font-weight: 600; }
.health-warn { color: #fbbf24 !important; }
.health-crit { color: #f87171 !important; }
.health-sep { width: 1px; height: 14px; background: #2d3148; flex-shrink: 0; }
.runner-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; margin-right: 3px; vertical-align: middle; }
.runner-online  { background: #4ade80; }
.runner-offline { background: #ef4444; }
.runner-busy    { background: #f59e0b; }

/* CI queue panel */
.ci-panel {
  width: 250px; flex-shrink: 0;
  background: #13151f; border-right: 1px solid #2d3148;
  display: flex; flex-direction: column; overflow: hidden;
  transition: width .2s ease;
}
.ci-panel.collapsed { width: 36px; }
.ci-panel-header {
  padding: 10px 14px 8px;
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .08em; color: #64748b;
  border-bottom: 1px solid #2d3148; flex-shrink: 0;
  display: flex; align-items: center; justify-content: space-between;
}
.ci-panel.collapsed .ci-list,
.ci-panel.collapsed .ci-panel-header span { display: none; }
.ci-panel.collapsed .ci-collapse-btn { transform: scaleX(-1); }
.ci-list { overflow-y: auto; flex: 1; padding: 6px; display: flex; flex-direction: column; gap: 6px; }
.ci-section-label {
  font-size: 9px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .08em; color: #475569; padding: 4px 4px 2px;
}
.ci-run {
  background: #1a1d27; border: 1px solid #2d3148;
  border-radius: 6px; padding: 7px 9px;
}
.ci-run-branch {
  font-size: 11px; font-weight: 600; color: #e2e8f0;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.ci-run-meta { font-size: 10px; color: #64748b; margin-top: 2px; }
.ci-run-actions { display: flex; gap: 5px; margin-top: 6px; flex-wrap: wrap; }
.ci-btn {
  border: none; border-radius: 4px; padding: 3px 8px;
  font-size: 10px; font-weight: 600; cursor: pointer; transition: background .15s;
}
.ci-btn:disabled { opacity: .35; cursor: not-allowed; }
.ci-btn-bump   { background: #312e81; color: #a78bfa; }
.ci-btn-bump:hover:not(:disabled)   { background: #3730a3; }
.ci-btn-cancel { background: #450a0a; color: #fca5a5; }
.ci-btn-cancel:hover:not(:disabled) { background: #7f1d1d; }
.ci-btn-retry  { background: #052e16; color: #4ade80; }
.ci-btn-retry:hover:not(:disabled)  { background: #14532d; }
.ci-status-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; margin-right: 4px; vertical-align: middle; }
.ci-dot-running  { background: #4ade80; animation: pulse .9s infinite; }
.ci-dot-queued   { background: #f59e0b; }
.ci-dot-cancel   { background: #475569; }
</style>
</head>
<body>
<div id="auth-screen">
  <!-- Setup view: shown on first run before Google Authenticator is configured -->
  <div class="auth-box" id="setup-box" style="display:none">
    <h2>Agent Kanban</h2>
    <p>First-time setup — add Agent Kanban to Google Authenticator</p>
    <div class="step"><strong>1.</strong> Open Google Authenticator on your phone</div>
    <div class="step"><strong>2.</strong> Tap + → Enter a setup key</div>
    <div class="step"><strong>3.</strong> Account name: <strong>Agent Kanban</strong></div>
    <div class="step"><strong>4.</strong> Key (copy exactly):</div>
    <div class="secret-box" id="totp-secret">loading…</div>
    <div class="step"><strong>5.</strong> Key type: <strong>Time based</strong> → Add</div>
    <div class="step"><strong>6.</strong> Enter the 6-digit code shown in the app:</div>
    <input id="code-input" type="text" inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="one-time-code">
    <button id="auth-submit">Verify &amp; Unlock</button>
    <div id="auth-error"></div>
  </div>
  <!-- Login view: shown after setup is complete -->
  <div class="auth-box" id="login-box" style="display:none">
    <h2>Agent Kanban</h2>
    <p>Enter the 6-digit code from Google Authenticator</p>
    <input id="login-code-input" type="text" inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="one-time-code">
    <button id="login-submit">Unlock</button>
    <div id="login-error"></div>
  </div>
</div>
<header>
  <h1>Agent Kanban</h1>
  <span class="pause-badge" id="pause-badge">PAUSED</span>
  <div class="spacer"></div>
  <span id="updated"></span>
  <button class="hbtn hbtn-pause"   id="btn-pause">Pause All</button>
  <button class="hbtn hbtn-unpause" id="btn-unpause">Unpause</button>
  <button class="hbtn" id="btn-proposals" style="background:#312e81;color:#a78bfa">Proposals<span id="proposals-count">0</span></button>
  <span id="status">connecting…</span>
</header>
<div id="health-bar">
  <div class="health-item" id="h-cpu">CPU –</div>
  <div class="health-sep"></div>
  <div class="health-item" id="h-ram">RAM –</div>
  <div class="health-sep"></div>
  <div class="health-item" id="h-swap">Swap –</div>
  <div class="health-sep"></div>
  <div class="health-item" id="h-disk">Disk –</div>
  <div class="health-sep"></div>
  <div class="health-item" id="h-r1">Runner 1 –</div>
  <div class="health-sep"></div>
  <div class="health-item" id="h-r2">Runner 2 –</div>
  <div class="health-sep"></div>
  <div class="health-item" id="h-updated" style="color:#3d4462"></div>
</div>
<div id="proposals-panel" class="hidden">
  <div class="proposals-inner">
    <div class="proposals-toolbar">
      <h2>Proposals</h2>
      <button class="close-btn" id="close-proposals-btn">&#x2715;</button>
    </div>
    <div class="proposals-list" id="proposals-list">
      <div style="font-size:11px;color:#3d4462;text-align:center;padding:24px">Loading&hellip;</div>
    </div>
  </div>
</div>
<div class="main">
  <div class="ci-panel" id="ci-panel">
    <div class="ci-panel-header">
      <span>CI Queue</span>
      <button class="collapse-btn ci-collapse-btn" id="ci-collapse-btn" title="Collapse">&#x276F;</button>
    </div>
    <div class="ci-list" id="ci-list"><div class="empty">loading&hellip;</div></div>
  </div>
  <div class="board" id="board"></div>
  <div class="agent-panel">
    <div class="agent-panel-header">
      <span>Agents</span>
      <button class="collapse-btn" id="collapse-btn" title="Collapse">&#x276F;</button>
    </div>
    <div class="agent-list" id="agent-list"></div>
  </div>
</div>
<script>
const COLS = [
  { key: 'Ready',             cls: 'col-ready' },
  { key: 'In Progress',       cls: 'col-in-progress' },
  { key: 'In Review',         cls: 'col-in-review' },
  { key: 'Changes Requested', cls: 'col-changes-requested' },
  { key: 'Pending Human',     cls: 'col-pending-human' },
  { key: 'Approved',          cls: 'col-approved' },
  { key: "Owner's Queue",     cls: 'col-keiths-queue' },
  { key: 'Shipped',           cls: 'col-shipped' },
];

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function priorityBadge(p) {
  if (!p) return '';
  const cls = p.startsWith('P0') ? 'p0' : p.startsWith('P1') ? 'p1' : 'p2';
  return \`<span class="badge \${cls}">\${p.split('-')[0]}</span>\`;
}

function renderCard(card) {
  const pr = card.pr && !card.pr.startsWith('(') ? card.pr : null;
  const prMatch = pr && pr.match(/#(\\d+)/);
  const prLink = prMatch ? \`<a href="https://github.com/YOUR_GITHUB_ORG/YOUR_REPO/pull/\${prMatch[1]}" target="_blank">PR #\${prMatch[1]}</a>\` : '';
  return \`<div class="card \${card.type}" data-id="\${esc(card.id)}" data-title="\${esc(card.title)}">
    <div class="card-id">\${card.type==='bug'?'<span class="badge bug-type">BUG</span>':card.type==='audit'?'<span class="badge audit-type">AUDIT</span>':''}\${esc(card.id)}</div>
    <div class="card-title">\${esc(card.title)}</div>
    <div class="card-meta">\${priorityBadge(card.priority)}\${prLink}</div>
    <div class="card-controls">
      <button class="reorder-btn" data-dir="top" title="Move to top">⤒ top</button>
      <button class="reorder-btn" data-dir="up" title="Move up">▲</button>
      <button class="reorder-btn" data-dir="down" title="Move down">▼</button>
    </div>
  </div>\`;
}

function renderBoard(data) {
  const board = document.getElementById('board');
  board.innerHTML = '';
  for (const { key, cls } of COLS) {
    const cards = data.columns[key] || [];
    const col = document.createElement('div');
    col.className = \`column \${cls}\`;
    col.innerHTML = \`
      <div class="col-header" data-col="\${key}"><span>\${key}</span><span class="col-count">\${cards.length}</span></div>
      <div class="col-body">\${cards.length ? cards.map(renderCard).join('') : '<div class="empty">empty</div>'}</div>\`;
    board.appendChild(col);
  }
  if (data.ts) document.getElementById('updated').textContent = 'Updated ' + new Date(data.ts).toLocaleTimeString();

  // Reorder buttons (▲ ▼ ⤒)
  board.querySelectorAll('.reorder-btn').forEach(function(btn) {
    btn.addEventListener('click', async function(e) {
      e.stopPropagation();
      const card = btn.closest('.card');
      await authFetch('/api/reorder-card', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cardId: card.dataset.id, direction: btn.dataset.dir })
      }).catch(() => null);
    });
  });

  // Card click-to-select
  board.querySelectorAll('.card').forEach(function(el) {
    el.addEventListener('click', function(e) {
      e.stopPropagation();
      const id = el.dataset.id;
      if (selectedCardId === id) {
        clearSelection();
      } else {
        selectedCardId = id;
        board.querySelectorAll('.card').forEach(function(c) { c.classList.toggle('selected', c.dataset.id === id); });
        board.querySelectorAll('.col-header').forEach(function(h) { h.classList.add('drop-target'); });
      }
    });
  });

  // Column header click-to-drop
  board.querySelectorAll('.col-header').forEach(function(h) {
    h.addEventListener('click', async function() {
      if (!selectedCardId) return;
      const targetCol = h.dataset.col;
      const id = selectedCardId;
      clearSelection();
      const r = await authFetch('/api/move-card', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cardId: id, targetColumn: targetCol })
      }).catch(() => null);
    });
  });
}

// Card selection
let selectedCardId = null;
function clearSelection() {
  selectedCardId = null;
  document.querySelectorAll('.card.selected').forEach(function(c) { c.classList.remove('selected'); });
  document.querySelectorAll('.col-header.drop-target').forEach(function(h) { h.classList.remove('drop-target'); });
}
document.addEventListener('keydown', function(e) {
  if (e.key !== 'Escape') return;
  // Close proposals panel if open
  const proposalsPanel = document.getElementById('proposals-panel');
  if (!proposalsPanel.classList.contains('hidden')) {
    proposalsPanel.classList.add('hidden');
    return;
  }
  // Collapse agent sidebar if expanded
  const agentPanel = document.querySelector('.agent-panel');
  if (!agentPanel.classList.contains('collapsed')) {
    agentPanel.classList.add('collapsed');
    localStorage.setItem('sidebar_collapsed', '1');
    return;
  }
  // Otherwise clear card selection
  clearSelection();
});

// Agent table
let agentData = [];
let serverTs = Date.now();
let localTs  = Date.now();

function fmtSecs(s) {
  s = Math.max(0, Math.round(s));
  const m = Math.floor(s / 60), h = Math.floor(m / 60);
  if (h > 0) return h + 'h' + (m%60 ? String(m%60).padStart(2,'0') + 'm' : '');
  if (m > 0) return m + 'm' + String(s%60).padStart(2,'0') + 's';
  return s + 's';
}

function renderAgents() {
  const elapsed = (Date.now() - localTs) / 1000;
  const list = document.getElementById('agent-list');
  list.innerHTML = '';
  for (const a of agentData) {
    const live = Math.max(0, a.secsUntil - elapsed);
    const pct  = Math.min(1, Math.max(0, 1 - live / a.maxSecs));
    const cntCls = live < 30 ? 'urgent' : live < 120 ? 'soon' : '';
    const row = document.createElement('div');
    row.className = 'agent-row';
    row.dataset.id = a.id;
    row.innerHTML = \`
      <div class="agent-dot" style="background:\${a.color}"></div>
      <div class="agent-name">\${esc(a.name)}</div>
      <span class="agent-status status-\${a.status}">\${a.status}</span>
      <span class="agent-countdown \${cntCls}">\${a.status==='running'?'…':fmtSecs(live)}</span>
      <button class="run-btn" data-id="\${a.id}" \${a.status==='running'?'disabled':''}>▶</button>\`;
    list.appendChild(row);

    if (a.hint) {
      const hint = document.createElement('div');
      hint.className = 'agent-hint';
      hint.textContent = '↳ ' + a.hint;
      list.appendChild(hint);
    }

    const bar = document.createElement('div');
    bar.className = 'agent-bar';
    bar.innerHTML = \`<div class="agent-bar-fill" style="width:\${Math.round(pct*100)}%;background:\${a.color}44"></div>\`;
    list.appendChild(bar);
  }

  // Attach trigger buttons
  list.querySelectorAll('.run-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.disabled = true;
      authFetch('/api/trigger/' + btn.dataset.id, { method: 'POST' }).catch(() => {});
    });
  });
}

// Tick every second to update countdowns
setInterval(renderAgents, 1000);

// Auth
let authToken = sessionStorage.getItem('kanban_token') || '';

function authFetch(url, opts = {}) {
  return fetch(url, { ...opts, headers: { ...(opts.headers||{}), 'Authorization': 'Bearer ' + authToken } });
}

function connectWs() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(\`\${proto}://\${location.host}?token=\${encodeURIComponent(authToken)}\`);
  const statusEl = document.getElementById('status');
  ws.onopen = () => { statusEl.textContent = 'live'; statusEl.className = 'connected'; };
  ws.onclose = (e) => {
    if (e.code === 4001) { sessionStorage.removeItem('kanban_token'); location.reload(); return; }
    statusEl.textContent = 'disconnected'; statusEl.className = '';
    setTimeout(connectWs, 3000);
  };
  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    renderBoard(data);
    agentData = data.agents || [];
    serverTs  = data.ts || Date.now();
    localTs   = Date.now();
    const paused = data.paused;
    document.getElementById('pause-badge').classList.toggle('visible', paused);
    document.getElementById('btn-pause').disabled = paused;
    document.getElementById('btn-unpause').disabled = !paused;
    renderAgents();
    if (typeof data.proposalsCount === 'number') {
      document.getElementById('proposals-count').textContent = data.proposalsCount;
      // Refresh list if panel is open
      if (!document.getElementById('proposals-panel').classList.contains('hidden')) {
        loadProposals();
      }
    }
    if (data.vps) renderHealthBar(data.vps, data.ci && data.ci.runners);
    if (data.ci)  renderCiPanel(data.ci);
  };
}

function showError(el, msg) {
  el.textContent = msg;
  el.style.display = msg ? 'block' : 'none';
}

function unlockApp(token) {
  authToken = token;
  sessionStorage.setItem('kanban_token', token);
  document.getElementById('auth-screen').classList.add('hidden');
  connectWs();
  refreshProposalsCount();
}

// Setup flow (first time)
async function submitSetup() {
  const code = document.getElementById('code-input').value.trim();
  if (code.length !== 6) return;
  const errEl = document.getElementById('auth-error');
  showError(errEl, '');
  try {
    const r = await fetch('/api/setup', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }) });
    const d = await r.json();
    if (d.ok) { unlockApp(d.token); return; }
    showError(errEl, d.error || 'Invalid code — try again');
    document.getElementById('code-input').value = '';
    document.getElementById('code-input').focus();
  } catch (_) { showError(errEl, 'Network error — try again'); }
}

// Login flow (after setup)
async function submitLogin() {
  const code = document.getElementById('login-code-input').value.trim();
  if (code.length !== 6) return;
  const errEl = document.getElementById('login-error');
  showError(errEl, '');
  try {
    const r = await fetch('/api/auth', { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }) });
    const d = await r.json();
    if (d.ok) { unlockApp(d.token); return; }
    showError(errEl, d.error || 'Invalid code — try again');
    document.getElementById('login-code-input').value = '';
    document.getElementById('login-code-input').focus();
  } catch (_) { showError(errEl, 'Network error — try again'); }
}

document.getElementById('auth-submit').addEventListener('click', submitSetup);
document.getElementById('code-input').addEventListener('keydown', e => { if (e.key === 'Enter') submitSetup(); });
document.getElementById('login-submit').addEventListener('click', submitLogin);
document.getElementById('login-code-input').addEventListener('keydown', e => { if (e.key === 'Enter') submitLogin(); });

// On load: check token, then check setup status
(async () => {
  if (authToken) {
    document.getElementById('auth-screen').classList.add('hidden');
    connectWs();
    refreshProposalsCount();
    return;
  }
  const status = await fetch('/api/setup-status').then(r => r.json()).catch(() => ({}));
  if (status.configured) {
    document.getElementById('login-box').style.display = 'flex';
    document.getElementById('login-code-input').focus();
  } else {
    document.getElementById('totp-secret').textContent = status.secret || '';
    document.getElementById('setup-box').style.display = 'flex';
    document.getElementById('code-input').focus();
  }
})();

// Pause/unpause
document.getElementById('btn-pause').addEventListener('click', () => authFetch('/api/pause', { method: 'POST' }));
document.getElementById('btn-unpause').addEventListener('click', () => authFetch('/api/unpause', { method: 'POST' }));

// Proposals panel
let proposalsData = [];

async function refreshProposalsCount() {
  try {
    const r = await authFetch('/api/proposals');
    if (!r.ok) return;
    const data = await r.json();
    document.getElementById('proposals-count').textContent = data.length;
  } catch (_) {}
}

async function loadProposals() {
  try {
    const r = await authFetch('/api/proposals');
    if (!r.ok) return;
    proposalsData = await r.json();
    document.getElementById('proposals-count').textContent = proposalsData.length;
    renderProposals();
  } catch (_) {}
}

function renderProposals() {
  const list = document.getElementById('proposals-list');
  if (!proposalsData.length) {
    list.innerHTML = '<div style="font-size:11px;color:#3d4462;text-align:center;padding:24px">No proposals</div>';
    return;
  }
  list.innerHTML = proposalsData.map(function(p, i) {
    const typeCls = p.type === 'system' ? 'system' : 'proposal';
    const typeLabel = p.type === 'system' ? 'SYSTEM' : 'PROPOSAL';
    let bodyHtml = '';
    if (p.type === 'proposal') {
      if (p.context)  bodyHtml += '<div class="prop-field"><div class="prop-field-label">Context</div><div class="prop-field-value">' + esc(p.context) + '</div></div>';
      if (p.proposal) bodyHtml += '<div class="prop-field"><div class="prop-field-label">Proposal</div><div class="prop-field-value">' + esc(p.proposal) + '</div></div>';
      if (p.why)      bodyHtml += '<div class="prop-field"><div class="prop-field-label">Why it matters</div><div class="prop-field-value">' + esc(p.why) + '</div></div>';
      if (p.tradeoff) bodyHtml += '<div class="prop-field"><div class="prop-field-label">Tradeoff</div><div class="prop-field-value">' + esc(p.tradeoff) + '</div></div>';
    } else {
      const impactCls = 'impact-' + (p.impact||'').toLowerCase();
      const effortCls = 'effort-' + (p.effort||'').toLowerCase();
      if (p.impact || p.effort) {
        bodyHtml += '<div class="prop-badges">'
          + (p.impact ? '<span class="prop-badge ' + impactCls + '">Impact: ' + esc(p.impact) + '</span>' : '')
          + (p.effort ? '<span class="prop-badge ' + effortCls + '">Effort: ' + esc(p.effort) + '</span>' : '')
          + '</div>';
      }
      bodyHtml += '<div class="prop-field-value">' + esc(p.body) + '</div>';
    }
    return '<div class="prop-card" data-idx="' + i + '">'
      + '<div class="prop-card-header">'
      + '<span class="prop-type ' + typeCls + '">' + typeLabel + '</span>'
      + '<div class="prop-meta">'
      + '<div class="prop-title">' + esc(p.title) + '</div>'
      + '<div class="prop-sub">' + esc(p.date) + ' \xb7 ' + esc(p.role) + '</div>'
      + '</div></div>'
      + '<div class="prop-body">' + bodyHtml + '</div>'
      + '<div class="prop-actions">'
      + '<button class="prop-btn prop-btn-accept" data-idx="' + i + '" data-action="accept">\u2713 Accept</button>'
      + '<button class="prop-btn prop-btn-reject" data-idx="' + i + '" data-action="reject">\u2715 Reject</button>'
      + '<button class="prop-btn prop-btn-ask" data-idx="' + i + '" data-action="ask">? Ask</button>'
      + '</div></div>';
  }).join('');

  list.querySelectorAll('.prop-btn').forEach(function(btn) {
    btn.addEventListener('click', async function() {
      const idx = parseInt(btn.dataset.idx);
      const action = btn.dataset.action;
      const p = proposalsData[idx];
      if (!p) return;
      const card = btn.closest('.prop-card');
      const isAsk = action === 'ask';
      if (isAsk) { btn.disabled = true; btn.textContent = '\u2713 Sent'; }
      else card.querySelectorAll('.prop-btn').forEach(function(b) { b.disabled = true; });
      try {
        const r = await authFetch('/api/proposals/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ headerLine: p.headerLine, action: action,
            title: p.title, type: p.type, date: p.date, role: p.role })
        });
        const d = await r.json();
        if (d.ok && !isAsk) {
          card.style.opacity = '0.3';
          setTimeout(loadProposals, 400);
        } else if (!d.ok && !isAsk) {
          card.querySelectorAll('.prop-btn').forEach(function(b) { b.disabled = false; });
        } else if (isAsk) {
          setTimeout(function() { btn.disabled = false; btn.textContent = '? Ask'; }, 2000);
        }
      } catch (_) {
        if (isAsk) { btn.disabled = false; btn.textContent = '? Ask'; }
        else card.querySelectorAll('.prop-btn').forEach(function(b) { b.disabled = false; });
      }
    });
  });
}

document.getElementById('btn-proposals').addEventListener('click', function() {
  document.getElementById('proposals-panel').classList.remove('hidden');
  loadProposals();
});
document.getElementById('close-proposals-btn').addEventListener('click', function() {
  document.getElementById('proposals-panel').classList.add('hidden');
});
document.getElementById('proposals-panel').addEventListener('click', function(e) {
  if (e.target === document.getElementById('proposals-panel')) {
    document.getElementById('proposals-panel').classList.add('hidden');
  }
});

// Health bar + CI panel
function fmtBytes(b) {
  if (!b) return '–';
  if (b >= 1e9) return (b / 1e9).toFixed(1) + 'G';
  if (b >= 1e6) return (b / 1e6).toFixed(0) + 'M';
  return b + 'B';
}

function pct(used, total) { return total ? Math.round(used / total * 100) : 0; }

function healthCls(p) { return p >= 90 ? 'health-crit' : p >= 75 ? 'health-warn' : ''; }

function renderHealthBar(vps, runners) {
  if (!vps || !vps.mem) return;
  const ramPct  = pct(vps.mem.used,   vps.mem.total);
  const swapPct = pct(vps.swap.used,  vps.swap.total);
  const diskPct = pct(vps.disk.used,  vps.disk.total);
  const cpuPct  = vps.cpu.cores ? Math.round(vps.cpu.load1 / vps.cpu.cores * 100) : 0;

  document.getElementById('h-cpu').innerHTML =
    \`CPU <strong class="\${healthCls(cpuPct)}">\${vps.cpu.load1.toFixed(2)} (\${cpuPct}%)</strong>\`;
  document.getElementById('h-ram').innerHTML =
    \`RAM <strong class="\${healthCls(ramPct)}">\${fmtBytes(vps.mem.used)} / \${fmtBytes(vps.mem.total)} (\${ramPct}%)</strong>\`;
  document.getElementById('h-swap').innerHTML = vps.swap.total > 0
    ? \`Swap <strong class="\${healthCls(swapPct)}">\${fmtBytes(vps.swap.used)} / \${fmtBytes(vps.swap.total)}</strong>\`
    : 'Swap <strong style="color:#64748b">none</strong>';
  if (vps.disk.total > 0) {
    document.getElementById('h-disk').innerHTML =
      \`Disk <strong class="\${healthCls(diskPct)}">\${fmtBytes(vps.disk.used)} / \${fmtBytes(vps.disk.total)} (\${diskPct}%)</strong>\`;
  }

  if (runners && runners.length) {
    const r1 = runners.find(r => !/-2$/.test(r.name)) || runners[0];
    const r2 = runners.find(r =>  /-2$/.test(r.name));
    const runnerHtml = (r, label) => {
      if (!r) return \`\${label} <strong style="color:#3d4462">–</strong>\`;
      const offline = r.status !== 'online';
      const dotCls  = offline ? 'runner-offline' : r.busy ? 'runner-busy' : 'runner-online';
      return \`\${label} <span class="runner-dot \${dotCls}"></span><strong>\${offline ? 'offline' : r.busy ? 'busy' : 'idle'}</strong>\`;
    };
    document.getElementById('h-r1').innerHTML = runnerHtml(r1, 'Runner 1');
    document.getElementById('h-r2').innerHTML = runnerHtml(r2, 'Runner 2');
  }

  if (vps.ts) {
    document.getElementById('h-updated').textContent = 'health ' + new Date(vps.ts).toLocaleTimeString();
  }
}

function renderCiPanel(ci) {
  if (!ci) return;
  const list      = document.getElementById('ci-list');
  const running   = ci.queue.filter(r => r.status === 'in_progress');
  const queued    = ci.queue.filter(r => r.status === 'queued');
  const cancelled = ci.bumpCancelled || [];
  let html = '';

  const prTag = (r) => r.prs && r.prs[0] ? \` · PR #\${r.prs[0].number}\` : '';

  if (running.length) {
    html += '<div class="ci-section-label">Running</div>';
    for (const r of running) {
      html += \`<div class="ci-run">
        <div class="ci-run-branch"><span class="ci-status-dot ci-dot-running"></span>\${esc(r.branch)}</div>
        <div class="ci-run-meta">in progress\${prTag(r)}</div>
        <div class="ci-run-actions">
          <button class="ci-btn ci-btn-cancel" data-id="\${r.id}" data-action="cancel">✕ Cancel</button>
        </div></div>\`;
    }
  }
  if (queued.length) {
    html += '<div class="ci-section-label">Queued</div>';
    for (const r of queued) {
      html += \`<div class="ci-run">
        <div class="ci-run-branch"><span class="ci-status-dot ci-dot-queued"></span>\${esc(r.branch)}</div>
        <div class="ci-run-meta">queued\${prTag(r)}</div>
        <div class="ci-run-actions">
          <button class="ci-btn ci-btn-bump" data-id="\${r.id}" data-action="bump">↑ Bump</button>
          <button class="ci-btn ci-btn-cancel" data-id="\${r.id}" data-action="cancel">✕</button>
        </div></div>\`;
    }
  }
  if (cancelled.length) {
    html += '<div class="ci-section-label">Cancelled — retry?</div>';
    for (const r of cancelled) {
      html += \`<div class="ci-run">
        <div class="ci-run-branch"><span class="ci-status-dot ci-dot-cancel"></span>\${esc(r.branch)}</div>
        <div class="ci-run-meta">cancelled\${prTag(r)}</div>
        <div class="ci-run-actions">
          <button class="ci-btn ci-btn-retry" data-id="\${r.id}" data-action="retry">↺ Retry</button>
        </div></div>\`;
    }
  }
  if (!running.length && !queued.length && !cancelled.length) {
    html = '<div class="empty" style="font-size:10px;color:#3d4462;text-align:center;padding:16px">Queue empty</div>';
  }

  list.innerHTML = html;
  list.querySelectorAll('.ci-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try {
        await authFetch('/api/ci/' + btn.dataset.action, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ runId: parseInt(btn.dataset.id) }),
        });
      } catch (_) { btn.disabled = false; }
    });
  });
}

// CI panel collapse
const ciPanelEl = document.getElementById('ci-panel');
const ciCollapseBtn = document.getElementById('ci-collapse-btn');
if (localStorage.getItem('ci_collapsed') === '1') ciPanelEl.classList.add('collapsed');
ciCollapseBtn.addEventListener('click', () => {
  const c = ciPanelEl.classList.toggle('collapsed');
  localStorage.setItem('ci_collapsed', c ? '1' : '0');
});

// Collapse sidebar
const agentPanel = document.querySelector('.agent-panel');
const collapseBtn = document.getElementById('collapse-btn');
if (localStorage.getItem('sidebar_collapsed') === '1') agentPanel.classList.add('collapsed');
collapseBtn.addEventListener('click', () => {
  const collapsed = agentPanel.classList.toggle('collapsed');
  localStorage.setItem('sidebar_collapsed', collapsed ? '1' : '0');
});
</script>
</body>
</html>`;

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');

  // Public: serve shell page
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(HTML);
  }

  // Public: TOTP setup status
  if (req.method === 'GET' && req.url === '/api/setup-status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      configured: isConfigured(),
      otpauth: isConfigured() ? null : otpauthUrl(),
      secret: isConfigured() ? null : TOTP_SECRET,
    }));
  }

  // Public: complete TOTP setup (verify first code)
  if (req.method === 'POST' && req.url === '/api/setup') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { code } = JSON.parse(body);
        if (verifyTOTP(TOTP_SECRET, code)) {
          markConfigured();
          const token = makeToken();
          sessions.add(token);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: true, token }));
        }
      } catch (_) {}
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid code — check your authenticator app' }));
    });
    return;
  }

  // Public: TOTP auth
  if (req.method === 'POST' && req.url === '/api/auth') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { code } = JSON.parse(body);
        if (isConfigured() && verifyTOTP(TOTP_SECRET, code)) {
          const token = makeToken();
          sessions.add(token);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: true, token }));
        }
      } catch (_) {}
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid code' }));
    });
    return;
  }

  // All other API endpoints require auth
  if (!validToken(req)) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }

  if (req.method === 'POST' && req.url.startsWith('/api/trigger/')) {
    return triggerAgent(req.url.slice('/api/trigger/'.length), res);
  }
  if (req.method === 'POST' && req.url === '/api/pause') {
    try { fs.writeFileSync(path.join(AGENTS_DIR, 'PAUSE'), ''); } catch (_) {}
    broadcastState();
    res.writeHead(200); return res.end('ok');
  }
  if (req.method === 'POST' && req.url === '/api/unpause') {
    ['PAUSE','DEV_PAUSE','REV_PAUSE','TRD_PAUSE','MW_PAUSE','PM_PAUSE',
     'DEV_IDLE','REV_IDLE','TRD_IDLE','MW_IDLE','PM_IDLE']
      .forEach(f => { try { fs.unlinkSync(path.join(AGENTS_DIR, f)); } catch (_) {} });
    broadcastState();
    res.writeHead(200); return res.end('ok');
  }
  if (req.method === 'POST' && req.url === '/api/move-card') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { cardId, targetColumn } = JSON.parse(body);
        if (!cardId || !targetColumn) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: false }));
        }
        const ok = moveCard(cardId, targetColumn);
        broadcastState();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok }));
      } catch (_) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }

  if (req.method === 'POST' && req.url === '/api/reorder-card') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { cardId, direction } = JSON.parse(body);
        if (!cardId || !['up', 'down', 'top', 'bottom'].includes(direction)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: false }));
        }
        const ok = reorderCard(cardId, direction);
        broadcastState();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok }));
      } catch (_) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }

  if (req.method === 'GET' && req.url === '/api/proposals') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(parseProposals()));
  }

  if (req.method === 'POST' && req.url === '/api/proposals/action') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { headerLine, action, title, type, date, role } = JSON.parse(body);
        if (!headerLine || !['accept', 'reject', 'ask'].includes(action)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: false, error: 'Invalid request' }));
        }
        if (action === 'ask') {
          const typeLabel = type === 'system' ? 'System improvement' : 'Proposal';
          const msg = `❓ **Question about:** ${title}\n${typeLabel} · ${date} · ${role}\n_What would you like to know?_`;
          spawn('node', [path.join(WORKSPACE, 'scripts/discord-post.js'), process.env.PROPOSALS_CHANNEL_ID || 'YOUR_PROPOSALS_CHANNEL_ID', msg],
            { cwd: WORKSPACE, stdio: 'ignore',
              env: { ...process.env, HOME: process.env.HOME || require('os').homedir() } });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: true }));
        }
        const ok = removeProposal(headerLine);
        if (ok && action === 'accept') {
          const typeLabel = type === 'system' ? 'System improvement' : 'Proposal';
          const msg = `✓ **Accepted:** ${title}\n${typeLabel} · ${date} · ${role}`;
          spawn('node', [path.join(WORKSPACE, 'scripts/discord-post.js'), process.env.PROPOSALS_CHANNEL_ID || 'YOUR_PROPOSALS_CHANNEL_ID', msg],
            { cwd: WORKSPACE, stdio: 'ignore',
              env: { ...process.env, HOME: process.env.HOME || require('os').homedir() } });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok }));
      } catch (_) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }

  // CI: bump one run to front (cancel all other queued runs)
  if (req.method === 'POST' && req.url === '/api/ci/bump') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { runId } = JSON.parse(body);
        const toCancel = ciCache.queue.filter(r => r.id !== runId && r.status === 'queued');
        for (const r of toCancel) {
          if (!ciCache.bumpCancelled.find(x => x.id === r.id)) ciCache.bumpCancelled.push(r);
          exec(`${GH} run cancel ${r.id} --repo YOUR_GITHUB_ORG/YOUR_REPO`,
            { env: { ...process.env, HOME: process.env.HOME || require('os').homedir() } }, () => {});
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, cancelled: toCancel.length }));
        setTimeout(refreshCi, 3000);
      } catch (_) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }

  // CI: cancel a single run
  if (req.method === 'POST' && req.url === '/api/ci/cancel') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { runId } = JSON.parse(body);
        exec(`${GH} run cancel ${runId} --repo YOUR_GITHUB_ORG/YOUR_REPO`,
          { env: { ...process.env, HOME: process.env.HOME || require('os').homedir() } }, () => {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        setTimeout(refreshCi, 3000);
      } catch (_) { res.writeHead(400); res.end('bad request'); }
    });
    return;
  }

  // CI: retry (rerun) a cancelled run
  if (req.method === 'POST' && req.url === '/api/ci/retry') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { runId } = JSON.parse(body);
        exec(`${GH} run rerun ${runId} --repo YOUR_GITHUB_ORG/YOUR_REPO`,
          { env: { ...process.env, HOME: process.env.HOME || require('os').homedir() } }, () => {});
        ciCache.bumpCancelled = ciCache.bumpCancelled.filter(r => r.id !== runId);
        broadcastState();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        setTimeout(refreshCi, 5000);
      } catch (_) { res.writeHead(400); res.end('bad request'); }
    });
    return;
  }

  res.writeHead(404); res.end('Not found');
});

// ---------------------------------------------------------------------------
// WebSocket + file watcher
// ---------------------------------------------------------------------------

const wss = new WebSocketServer({ server });
wss.on('connection', (ws, req) => {
  if (!validWsToken(req.url)) {
    ws.close(4001, 'Unauthorized');
    return;
  }
  ws.send(JSON.stringify({ ...readBoard(), agents: buildAgentStatus(), paused: isPaused(), vps: vpsCache, ci: ciCache, ts: Date.now() }));
});

// Push board updates when backlog or proposals change
let debounce = null;
fs.watchFile(BACKLOG_PATH, { interval: 1000 }, () => {
  clearTimeout(debounce);
  debounce = setTimeout(broadcastState, 300);
});
fs.watchFile(PROPOSALS_PATH, { interval: 1000 }, () => {
  clearTimeout(debounce);
  debounce = setTimeout(broadcastState, 300);
});

// Push agent status updates every 5s (keeps countdowns and lock states fresh)
setInterval(broadcastState, 5000);

// Refresh VPS health every 10s; CI queue every 30s
refreshVps();
refreshCi();
setInterval(refreshVps, 10_000);
setInterval(refreshCi, 30_000);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

server.listen(PORT, '0.0.0.0', () => console.log(`Agent Kanban → http://localhost:${PORT}`));
process.on('SIGINT', () => { fs.unwatchFile(BACKLOG_PATH); process.exit(0); });
