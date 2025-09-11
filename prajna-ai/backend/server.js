require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const axios = require("axios");
const https = require("https");
const OpenAI = require("openai");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const pdfParse = require("pdf-parse");
const mammoth = require("mammoth");
const { parse: csvParse } = require("csv-parse/sync");
const { exec, execFile } = require("child_process");
const {
  initApiKeysFile,
  getApiKeys,
  saveApiKeys,
  validateOpenAIKey,
  validateGeminiKey,
  validateClaudeKey,
  getAvailableModels,
} = require("./auth");

const app = express();
const PORT = process.env.PORT || 5000;

// tgpt configuration - try common paths
const TGPT_PATH = process.env.TGPT_PATH || (() => {
  const commonPaths = [
    "/usr/local/bin/tgpt",
    "/usr/bin/tgpt", 
    "/home/ltsu/.local/bin/tgpt",
    "/opt/tgpt/tgpt",
    "tgpt" // fallback to PATH
  ];
  return commonPaths[0]; // Use first path, will be checked at runtime
})();
const TGPT_TIMEOUT_MS = Number(process.env.TGPT_TIMEOUT_MS || 12000); // 12s for quicker responses
const TGPT_MAX_BUFFER = Number(process.env.TGPT_MAX_BUFFER || 10 * 1024 * 1024); // 10MB

app.use(cors());
app.use(bodyParser.json());
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
});
initApiKeysFile();
const DATA_DIR = path.join(__dirname, "data");
const HISTORY_FILE = path.join(DATA_DIR, "history.json");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(HISTORY_FILE)) fs.writeFileSync(HISTORY_FILE, JSON.stringify({ chats: [] }, null, 2));

// Configuration
const config = {
  splunk: {
    host: process.env.SPLUNK_HOST || "https://127.0.0.1:8089",
    username: process.env.SPLUNK_USER || "admin",
    password: process.env.SPLUNK_PASS || "Ltsu@123",
    index: process.env.SPLUNK_INDEX || "main",
    timeout: 30000,
  },
  tgpt: {
    path: TGPT_PATH,
    timeoutMs: TGPT_TIMEOUT_MS,
    maxBuffer: TGPT_MAX_BUFFER,
  }
};

console.log("🔧 Configuration loaded:", {
  splunkHost: config.splunk.host,
  splunkUser: config.splunk.username,
  splunkIndex: config.splunk.index,
  tgptPath: config.tgpt.path,
  tgptTimeoutMs: config.tgpt.timeoutMs,
});

// AI Clients Management
let openaiClient = null;
let activeModel = null;

function initializeAIClients() {
  const apiKeys = getApiKeys();
  if (apiKeys.openai.valid && apiKeys.openai.key) {
    openaiClient = new OpenAI({ apiKey: apiKeys.openai.key });
    activeModel = coerceOpenAIModel(apiKeys.openai.model);
  }
}

// Map deprecated/unsupported OpenAI model names to safe defaults
function coerceOpenAIModel(model) {
  const fallback = 'gpt-4o-mini';
  if (!model) return fallback;
  const m = String(model).toLowerCase();
  const map = {
    'gpt-4': 'gpt-4o-mini',
    'gpt-4-0613': 'gpt-4o-mini',
    'gpt-4-1106-preview': 'gpt-4o-mini',
    'gpt-3.5-turbo': 'gpt-4o-mini',
    'gpt-3.5-turbo-16k': 'gpt-4o-mini'
  };
  return map[m] || model;
}

// Allowed tgpt flags (top-level for reuse)
const allowedFlags = {
  img: "--img",
  shell: "--shell",
  code: "--code",
  quiet: "--quiet",
  whole: "--whole",
};

// --- Simple per-IP rate limiter (no external deps) ---
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = Number(process.env.RATE_LIMIT_RPM || 30); // per IP per minute
const ipToRequests = new Map();

function rateLimitMiddleware(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = ipToRequests.get(ip) || [];
  const recent = entry.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  recent.push(now);
  ipToRequests.set(ip, recent);
  if (recent.length > RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({ error: 'Too many requests, please slow down.' });
  }
  return next();
}

// Apply to chat-like endpoints
app.use(['/chat','/query','/analyze-file'], rateLimitMiddleware);

// --- Minimal concurrency queue for OpenAI calls ---
const MAX_CONCURRENT_OPENAI = Number(process.env.MAX_CONCURRENT_OPENAI || 2);
let openaiInFlight = 0;
const openaiQueue = [];

function enqueueOpenAI(taskFn) {
  return new Promise((resolve, reject) => {
    openaiQueue.push({ taskFn, resolve, reject });
    drainOpenAIQueue();
  });
}

function drainOpenAIQueue() {
  while (openaiInFlight < MAX_CONCURRENT_OPENAI && openaiQueue.length > 0) {
    const { taskFn, resolve, reject } = openaiQueue.shift();
    openaiInFlight++;
    Promise.resolve()
      .then(taskFn)
      .then((val) => resolve(val))
      .catch((err) => reject(err))
      .finally(() => {
        openaiInFlight--;
        setImmediate(drainOpenAIQueue);
      });
  }
}

// --- Retry with exponential backoff helper ---
async function withBackoff(fn, shouldRetry, attempts = 3, baseDelayMs = 1000) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      if (!shouldRetry(e) || i === attempts - 1) break;
      const delay = baseDelayMs * Math.pow(2, i);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

// --- Summarize text via tgpt (no API quota) ---
async function summarizeWithTgpt(promptText) {
  const { spawn } = require('child_process');
  const safe = String(promptText || '').slice(0, 8000);
  const args = buildTgptArgs(null, {}, `Summarize these Splunk logs for a SOC analyst. Be concise, bullet key findings and anomalies.\n\n${safe}`);
  return new Promise((resolve, reject) => {
    const child = spawn(config.tgpt.path, args, { stdio: ['ignore','pipe','pipe'], env: { ...process.env, TERM: 'dumb' } });
    let out = '';
    let err = '';
    let done = false;
    const finish = (val) => { if (done) return; done = true; try { child.kill('SIGKILL'); } catch(_){} resolve(val); };
    const timer = setTimeout(() => {
      const text = (out || err).trim() || '(No output from tgpt)';
      finish(`${text}\n\n(note: summary timed out, partial output shown)`);
    }, config.tgpt.timeoutMs);
    child.stdout.on('data', d => { out += d.toString(); });
    child.stderr.on('data', d => { err += d.toString(); });
    child.on('close', () => { clearTimeout(timer); const text = (out || err).trim() || '(No output from tgpt)'; finish(text); });
    child.on('error', e => { clearTimeout(timer); return reject(e); });
  });
}

// --- Summaries and Chat via OpenAI/Gemini with fallbacks ---
async function summarizeWithOpenAI(text) {
  if (!openaiClient) throw new Error('openai not configured');
  const execFn = () => openaiClient.chat.completions.create({
    model: activeModel || "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are a Senior SOC Analyst. Summarize logs concisely with key findings as bullet points." },
      { role: "user", content: String(text).slice(0, 12000) }
    ],
    max_tokens: 500
  });
  const response = await enqueueOpenAI(() => withBackoff(
    execFn,
    (e) => {
      const msg = (e && e.message) || '';
      const status = (e && e.status) || (e && e.response && e.response.status);
      return status === 429 || /rate|quota/i.test(msg);
    },
    3,
    800
  ));
  return response.choices[0].message.content;
}

async function summarizeWithGemini(text) {
  const keys = getApiKeys();
  if (!keys.gemini || !keys.gemini.valid || !keys.gemini.key) throw new Error('gemini not configured');
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${keys.gemini.key}`;
  const body = {
    contents: [
      { parts: [{ text: "Summarize logs concisely with key SOC findings as bullet points.\n\n" + String(text).slice(0, 12000) }] }
    ]
  };
  const exec = () => axios.post(url, body, { timeout: 12000 });
  const res = await withBackoff(exec, (e) => {
    const status = e && (e.status || (e.response && e.response.status));
    const msg = (e && e.message) || '';
    return status === 429 || /rate|quota/i.test(msg);
  }, 3, 800);
  const candidates = res && res.data && res.data.candidates || [];
  const content = candidates[0] && candidates[0].content && candidates[0].content.parts && candidates[0].content.parts[0] && candidates[0].content.parts[0].text;
  return content || '(No summary)';
}

async function chatWithOpenAI(message) {
  if (!openaiClient) throw new Error('openai not configured');
  const execFn = () => openaiClient.chat.completions.create({
    model: activeModel || "gpt-4o-mini",
    messages: [{ role: "user", content: message }],
    max_tokens: 500,
  });
  const response = await enqueueOpenAI(() => withBackoff(
    execFn,
    (e) => {
      const msg = (e && e.message) || '';
      const status = (e && e.status) || (e && e.response && e.response.status);
      return status === 429 || /rate|quota/i.test(msg);
    },
    3,
    800
  ));
  return response.choices[0].message.content;
}

async function chatWithGemini(message) {
  const keys = getApiKeys();
  if (!keys.gemini || !keys.gemini.valid || !keys.gemini.key) throw new Error('gemini not configured');
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${keys.gemini.key}`;
  const body = { contents: [{ parts: [{ text: String(message) }] }] };
  const exec = () => axios.post(url, body, { timeout: 12000 });
  const res = await withBackoff(exec, (e) => {
    const status = e && (e.status || (e.response && e.response.status));
    const msg = (e && e.message) || '';
    return status === 429 || /rate|quota/i.test(msg);
  }, 3, 800);
  const candidates = res && res.data && res.data.candidates || [];
  const content = candidates[0] && candidates[0].content && candidates[0].content.parts && candidates[0].content.parts[0] && candidates[0].content.parts[0].text;
  return content || '(No response)';
}

// Splunk Client
const splunkClient = axios.create({
  baseURL: config.splunk.host,
  auth: { username: config.splunk.username, password: config.splunk.password },
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: config.splunk.timeout,
});

// Splunk Helper Functions
async function testSplunkConnection() {
  try {
    console.log("🔌 Testing Splunk connection...");
    const response = await splunkClient.get(
      "/services/server/info?output_mode=json"
    );
    console.log("✅ Splunk connection successful");
    return true;
  } catch (error) {
    console.error("❌ Splunk connection failed:", error.message);
    return false;
  }
}

async function createSearchJob(query) {
  try {
    console.log("🔍 Creating search job:", query);
    const response = await splunkClient.post(
      "/services/search/jobs",
      `search=${encodeURIComponent(query)}&output_mode=json`
    );
    return response.data.sid;
  } catch (error) {
    console.error("❌ Failed to create search job:", error.message);
    throw error;
  }
}

async function waitForJobCompletion(sid, maxRetries = 25) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await splunkClient.get(
        `/services/search/jobs/${sid}?output_mode=json`
      );
      const status = response.data.entry[0].content.dispatchState;
      console.log(`🔄 Job status: ${status} (attempt ${attempt})`);
      if (status === "DONE") return true;
      if (status === "FAILED") throw new Error("Search job failed");
      await new Promise((resolve) => setTimeout(resolve, 2000));
    } catch (error) {
      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        continue;
      }
      throw error;
    }
  }
  throw new Error("Job timeout");
}

async function getSearchResults(sid) {
  try {
    const response = await splunkClient.get(
      `/services/search/jobs/${sid}/results?output_mode=json&count=20`
    );
    return response.data.results || [];
  } catch (error) {
    console.error("❌ Failed to get search results:", error.message);
    return [];
  }
}

async function executeSplunkSearch(query) {
  try {
    const sid = await createSearchJob(query);
    await waitForJobCompletion(sid);
    return await getSearchResults(sid);
  } catch (error) {
    console.error("❌ Splunk search failed:", error.message);
    return [];
  }
}

// Advanced Query Generation
function generateAdvancedSplunkQuery(userMessage) {
  const original = String(userMessage || '');
  const text = original
    .replace(/[’‘]/g, "'")
    .replace(/“|”/g, '"')
    .toLowerCase();

  // --- Time parsing ---
  let earliest = 'earliest=-24h@h';
  let latest = 'latest=now';

  // last N units
  const lastN = text.match(/last\s+(\d+)\s*(minutes|minute|mins|min|hours|hour|hrs|hr|days|day|weeks|week|months|month)/);
  if (lastN) {
    const n = parseInt(lastN[1], 10);
    const unitMap = { minute: 'm', minutes: 'm', mins: 'm', min: 'm', hour: 'h', hours: 'h', hr: 'h', hrs: 'h', day: 'd', days: 'd', week: 'w', weeks: 'w', month: 'mon', months: 'mon' };
    const u = unitMap[lastN[2]] || 'h';
    earliest = `earliest=-${n}${u}${u === 'mon' ? '' : '@' + u}`;
    latest = 'latest=now';
  }

  if (/today\b/.test(text) || /today's/.test(text)) { earliest = 'earliest=@d'; latest = 'latest=now'; }
  if (/yesterday\b/.test(text)) { earliest = 'earliest=-1d@d'; latest = 'latest=@d'; }
  if (/this\s+week/.test(text)) { earliest = 'earliest=@w0'; latest = 'latest=now'; }
  if (/last\s+week/.test(text)) { earliest = 'earliest=@w0-1w'; latest = 'latest=@w0'; }
  if (/this\s+month/.test(text)) { earliest = 'earliest=@mon'; latest = 'latest=now'; }
  if (/last\s+month/.test(text)) { earliest = 'earliest=@mon-1mon'; latest = 'latest=@mon'; }

  // Between dates
  const between = text.match(/(from|between)\s+(\d{4}-\d{2}-\d{2})\s+(to|and)\s+(\d{4}-\d{2}-\d{2})/);
  if (between) {
    earliest = `earliest=${between[2]}T00:00:00`;
    latest = `latest=${between[4]}T23:59:59`;
  }

  // Specific exact date
  const exactDate = text.match(/on\s+(\d{4}-\d{2}-\d{2})/);
  if (exactDate) {
    earliest = `earliest=${exactDate[1]}T00:00:00`;
    latest = `latest=${exactDate[1]}T23:59:59`;
  }

  // Index, sourcetype, host, source
  const indexMatch = original.match(/index[:=]\s*([\w\-*]+)/i);
  const sourcetypeMatch = original.match(/sourcetype[:=]\s*([\w\-*]+)/i);
  const hostMatch = original.match(/host[:=]\s*([\w\-\.]+)/i);
  const sourceMatch = original.match(/source[:=]\s*([^\s]+)/i);
  const indexStr = indexMatch ? indexMatch[1] : (config.splunk.index || '*');

  const filters = [];
  if (sourcetypeMatch) filters.push(`sourcetype=${sourcetypeMatch[1]}`);
  if (hostMatch) filters.push(`host=${hostMatch[1]}`);
  if (sourceMatch) filters.push(`source=${sourceMatch[1]}`);

  // Entity extraction
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;
  const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/gi;
  const hashRegex = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi; // md5/sha1/sha256
  const portRegex = /\bport\s*(\d{1,5})\b/i;
  const statusCodeRegex = /\bstatus\s*(\d{3})\b/i;
  const methodRegex = /\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/i;

  const ips = original.match(ipRegex) || [];
  const cves = original.match(cveRegex) || [];
  const hashes = original.match(hashRegex) || [];
  const port = original.match(portRegex);
  const statusCode = original.match(statusCodeRegex);
  const method = original.match(methodRegex);

  ips.forEach(ip => filters.push(`(src=${ip} OR dest=${ip} OR ip=${ip})`));
  cves.forEach(c => filters.push(`("${c}")`));
  hashes.forEach(h => filters.push(`("${h}")`));
  if (port) filters.push(`(dest_port=${port[1]} OR src_port=${port[1]} OR port=${port[1]})`);
  if (statusCode) filters.push(`status=${statusCode[1]}`);
  if (method) filters.push(`method=${method[1]}`);

  // Keywords
  const stop = new Set([
    'show','logs','log','of','for','the','in','any','all','time','times','today','yesterday','this','week','month','between','from','to','and','on','please','check','find','get','last','report','summarize','list','showme','give','me','a','an','is','are','with','without','by','at','current','now','earliest','latest','search'
  ]);
  const cleaned = original
    .replace(/index[:=].*/i, '')
    .replace(/sourcetype[:=].*/i, '')
    .replace(/host[:=].*/i, '')
    .replace(/source[:=].*/i, '')
    .replace(/from\s+\d{4}-\d{2}-\d{2}.*/i, '')
    .replace(/last\s+\d+\s+\w+/i, '')
    .replace(/today'?s?/i, '')
    .trim();

  const rawTerms = cleaned.split(/\s+/).filter(Boolean).map(t => t.toLowerCase());
  const terms = rawTerms.filter(t => t.length > 2 && !stop.has(t));
  const termExpr = terms
    .slice(0, 5) // keep broader query by limiting terms
    .map(t => `(${t} OR "${t}")`)
    .join(' ');

  const base = [`index=${indexStr}`, earliest, latest].concat(filters);
  const where = base.join(' ');
  const query = termExpr
    ? `search ${where} ${termExpr} | head 20`
    : `search ${where} | head 20`;
  return query;
}

// AI Analysis
async function analyzeLogs(userQuery, splunkQuery, logs) {
  try {
    if (!logs || logs.length === 0) return "No logs found for your query.";
    if (!openaiClient) return "AI service not configured. Please set up your API keys first.";

    const response = await openaiClient.chat.completions.create({
      model: activeModel || "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are a Senior SOC Analyst. Analyze logs and provide security summary in plain text.",
        },
        {
          role: "user",
          content: `User Request: "${userQuery}" Splunk Query: "${splunkQuery}" Logs: ${JSON.stringify(
            logs.slice(0, 15)
          )}`,
        },
      ],
      max_tokens: 800,
    });

    return response.choices[0].message.content;
  } catch (error) {
    console.error("❌ AI analysis failed:", error.message);
    if (error.message.includes("Rate limit")) return "OpenAI rate limit exceeded.";
    if (error.message.includes("Incorrect API key"))
      return "API key validation failed.";
    return `Found ${logs.length} logs but encountered an error during analysis.`;
  }
}

// Authentication Endpoints
app.get("/api/auth/status", (req, res) => {
  const apiKeys = getApiKeys();
  res.json({
    configured:
      apiKeys.openai.valid || apiKeys.gemini.valid || apiKeys.claude.valid,
    providers: apiKeys,
  });
});

app.post("/api/auth/validate", async (req, res) => {
  try {
    const { provider, apiKey, model } = req.body;
    if (!provider || !apiKey)
      return res
        .status(400)
        .json({ error: "Provider and API key are required" });

    let isValid = false;
    switch (provider) {
      case "openai":
        isValid = await validateOpenAIKey(apiKey);
        break;
      case "gemini":
        isValid = await validateGeminiKey(apiKey);
        break;
      case "claude":
        isValid = await validateClaudeKey(apiKey);
        break;
      default:
        return res.status(400).json({ error: "Invalid provider" });
    }

    if (isValid) {
      const apiKeys = getApiKeys();
      apiKeys[provider] = {
        key: apiKey,
        model: model || apiKeys[provider].model,
        valid: true,
      };
      saveApiKeys(apiKeys);
      initializeAIClients();
    }

    res.json({ valid: isValid, provider });
  } catch (error) {
    console.error("Validation error:", error.message);
    res.status(500).json({ error: "Validation failed", details: error.message });
  }
});

app.get("/api/auth/models/:provider", (req, res) => {
  const { provider } = req.params;
  const models = getAvailableModels(provider);
  res.json({ provider, models });
});

app.post("/api/auth/update-model", (req, res) => {
  try {
    const { provider, model } = req.body;
    const apiKeys = getApiKeys();
    if (apiKeys[provider] && apiKeys[provider].valid) {
      apiKeys[provider].model = model;
      saveApiKeys(apiKeys);
      initializeAIClients();
      res.json({ success: true, provider, model });
    } else {
      res.status(400).json({ error: "Provider not configured" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to update model" });
  }
});

app.post("/api/auth/reset", (req, res) => {
  try {
    const { provider } = req.body;
    const apiKeys = getApiKeys();
    if (provider) {
      apiKeys[provider] = {
        key: "",
        model: apiKeys[provider].model,
        valid: false,
      };
    } else {
      Object.keys(apiKeys).forEach((key) => {
        apiKeys[key] = { key: "", model: apiKeys[key].model, valid: false };
      });
    }
    saveApiKeys(apiKeys);
    initializeAIClients();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Failed to reset configuration" });
  }
});

// Chat Endpoints
app.post("/chat", async (req, res) => {
  try {
    const { message } = req.body;
    if (!openaiClient)
      return res.status(400).json({ reply: "AI service not configured" });

    const execFn = () => openaiClient.chat.completions.create({
      model: activeModel || "gpt-4o-mini",
      messages: [{ role: "user", content: message }],
      max_tokens: 500,
    });
    const response = await enqueueOpenAI(() => withBackoff(
      execFn,
      (e) => {
        const msg = (e && e.message) || '';
        const status = (e && e.status) || (e && e.response && e.response.status);
        return status === 429 || /rate|quota/i.test(msg);
      },
      3,
      800
    ));

    res.json({ reply: response.choices[0].message.content });
  } catch (error) {
    console.error("❌ OpenAI error:", error.message);
    if (error.message.includes("Rate limit")) {
      res
        .status(429)
        .json({ reply: "OpenAI rate limit exceeded. Please try again later." });
    } else {
      res.status(500).json({ reply: "AI service temporarily unavailable." });
    }
  }
});

// ✅ FIXED buildTgptCommand with safe escaping
function buildTgptCommand(flag, options, prompt) {
  const escapeShellArg = (arg) => {
    if (!arg) return "";
    return `'${String(arg).replace(/'/g, `'\\''`)}'`;
  };

  let cmd = config.tgpt.path;
  if (flag && allowedFlags[flag]) cmd += ` ${allowedFlags[flag]}`;

  if (options && typeof options === "object") {
    Object.entries(options).forEach(([key, value]) => {
      if (
        [
          "out",
          "height",
          "width",
          "img_count",
          "img_negative",
          "img_ratio",
          "provider",
          "model",
          "key",
          "url",
          "preprompt",
        ].includes(key)
      ) {
        cmd += ` --${key} ${escapeShellArg(value)}`;
      }
    });
  }

  cmd += ` ${escapeShellArg(prompt)}`;
  return cmd;
}

function buildTgptArgs(flag, options, prompt) {
  const args = ['--quiet', '--provider', 'phind']; // Always add quiet flag and phind provider
  if (flag && allowedFlags[flag]) args.push(allowedFlags[flag]);
  if (options && typeof options === "object") {
    Object.entries(options).forEach(([key, value]) => {
      if (["out","height","width","img_count","img_negative","img_ratio","provider","model","key","url","preprompt"].includes(key)) {
        args.push(`--${key}`);
        if (value !== undefined && value !== null && value !== "") args.push(String(value));
      }
    });
  }
  args.push(String(prompt));
  return args;
}

app.post("/query", async (req, res) => {
  try {
    const { message, provider, tgptFlag, tgptOptions } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required" });

    console.log(`📨 Query: "${message}"`);

    const siemKeywords = [
      "splunk",
      "log",
      "logs",
      "alert",
      "security",
      "firewall",
      "network",
      "vulnerability",
      "CVE",
      "scan",
      "index",
      "sourcetype",
      "authentication",
      "summary",
      "date",
      "time",
      "file",
      "analyze",
    ];
    const isSiemQuery = siemKeywords.some((kw) =>
      message.toLowerCase().includes(kw)
    );

    if (provider === "tgpt") {
      let prompt = message;
      let flags = [];
      if (tgptFlag) {
        flags.push(tgptFlag);
      }
      let options = tgptOptions || {};

      // Skip Splunk enrichment for tgpt to reduce latency
      const args = buildTgptArgs(flags[0], options, prompt);
      console.log("Executing tgpt:", config.tgpt.path, args);
      
      const { spawn } = require('child_process');
      console.log("Spawning tgpt with args:", args);

      // Direct spawn (no shell) and manual timeout with partial output return
      const child = spawn(config.tgpt.path, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, TERM: 'dumb' }
      });

      let output = '';
      let errorOutput = '';
      let responded = false;

      const finish = (payloadFn) => {
        if (responded) return;
        responded = true;
        try { child.kill('SIGKILL'); } catch (e) {}
        return payloadFn();
      };

      const timer = setTimeout(() => {
        const cleaned = output.trim() || errorOutput.trim() || "(No output from tgpt)";
        finish(() => {
          if (tgptFlag === 'img' && options.out) return res.json({ success: true, imagePath: options.out, timedOut: true });
          return res.json({ success: true, reply: cleaned, timedOut: true });
        });
      }, config.tgpt.timeoutMs);

      child.stdout.on('data', (data) => { output += data.toString(); });
      child.stderr.on('data', (data) => { errorOutput += data.toString(); });

      child.on('close', (code) => {
        if (responded) return;
        clearTimeout(timer);
        console.log("tgpt result:", { code, out: output.substring(0, 100), err: errorOutput.substring(0, 100) });
        const cleaned = output.trim() || errorOutput.trim() || "(No output from tgpt)";
        if (code !== 0 && !cleaned) {
          return finish(() => res.status(500).json({ success: false, error: "tgpt error", details: `Exit code: ${code}` }));
        }
        return finish(() => {
          if (tgptFlag === 'img' && options.out) return res.json({ success: true, imagePath: options.out });
          return res.json({ success: true, reply: cleaned });
        });
      });

      child.on('error', (error) => {
        if (responded) return;
        clearTimeout(timer);
        console.log("tgpt spawn error:", error);
        return finish(() => res.status(500).json({ success: false, error: "tgpt spawn error", details: error.message }));
      });
      return;
    }

    // If not a SIEM (Splunk) query, prefer tgpt for natural conversation to avoid quotas; then fall back to OpenAI/Gemini.
    if (!isSiemQuery) {
      try {
        // tgpt first
        const args = buildTgptArgs(null, {}, message);
        const { spawn } = require('child_process');
        const child = spawn(config.tgpt.path, args, { stdio: ['ignore','pipe','pipe'], env: { ...process.env, TERM: 'dumb' } });
        let out = '', err = '';
        let done = false;
        const finish = (payload) => { if (done) return; done = true; try { child.kill('SIGKILL'); } catch(_){} return res.json(payload); };
        const timer = setTimeout(() => { const text = (out || err).trim() || '(No output)'; finish({ success: true, reply: text, timedOut: true }); }, config.tgpt.timeoutMs);
        child.stdout.on('data', d => { out += d.toString(); });
        child.stderr.on('data', d => { err += d.toString(); });
        child.on('close', async () => {
          clearTimeout(timer);
          const text = (out || err).trim();
          if (text) return finish({ success: true, reply: text });
          // if tgpt produced nothing, try OpenAI then Gemini
          try {
            if (openaiClient) {
              const reply = await chatWithOpenAI(message);
              return finish({ success: true, reply });
            }
            const keys = getApiKeys();
            if (keys.gemini && keys.gemini.valid && keys.gemini.key) {
              const reply = await chatWithGemini(message);
              return finish({ success: true, reply });
            }
            return finish({ success: true, reply: "Hello! How can I assist you today?" });
          } catch (_) {
            return finish({ success: true, reply: "Hello! How can I assist you today?" });
          }
        });
        child.on('error', async () => {
          // fallback to OpenAI/Gemini
          try {
            if (openaiClient) {
              const reply = await chatWithOpenAI(message);
              return res.json({ success: true, reply });
            }
            const keys = getApiKeys();
            if (keys.gemini && keys.gemini.valid && keys.gemini.key) {
              const reply = await chatWithGemini(message);
              return res.json({ success: true, reply });
            }
            return res.json({ success: true, reply: "Hello! How can I assist you today?" });
          } catch (e) {
            return res.json({ success: true, reply: "Hello! How can I assist you today?" });
          }
        });
        return;
      } catch (err) {
        return res.json({ success: true, reply: "Hello! How can I assist you today?" });
      }
    }

    const splunkQuery = generateAdvancedSplunkQuery(message);
    console.log(`🔍 Generated: ${splunkQuery}`);

    let logs = [];
    try {
      logs = await executeSplunkSearch(splunkQuery);
      console.log(`📊 Found ${logs.length} logs`);
    } catch (splunkError) {
      console.error("Splunk query error:", splunkError.message);
      return res.json({
        success: false,
        userQuery: message,
        splunkQuery: splunkQuery,
        logsCount: 0,
        summary: `Splunk error: ${splunkError.message}`,
        sampleLogs: [],
      });
    }

    if (!logs || logs.length === 0) {
      return res.json({
        success: true,
        userQuery: message,
        splunkQuery: splunkQuery,
        logsCount: 0,
        summary: "No logs found for your query.",
        sampleLogs: [],
      });
    }

    // Summarize Splunk logs using available LLM: OpenAI -> Gemini -> tgpt
    let summary = '';
    const summaryPayload = {
      userQuery: message,
      splunkQuery,
      sample: logs.slice(0, 20)
    };
    const serialized = JSON.stringify(summaryPayload, null, 2);
    try {
      if (openaiClient) {
        summary = await summarizeWithOpenAI(serialized);
      } else {
        const keys = getApiKeys();
        if (keys.gemini && keys.gemini.valid && keys.gemini.key) {
          summary = await summarizeWithGemini(serialized);
        } else {
          summary = await summarizeWithTgpt(serialized);
        }
      }
    } catch (_) {
      try { summary = await summarizeWithTgpt(serialized); } catch (e2) { summary = '(Failed to summarize logs)'; }
    }

    res.json({
      success: true,
      userQuery: message,
      splunkQuery: splunkQuery,
      logsCount: logs.length,
      summary,
      sampleLogs: logs.slice(0, 5)
    });
  } catch (error) {
    console.error("❌ Query processing failed:", error.message);
    res.status(500).json({ error: "Failed to process query", details: error.message });
  }
});

// File Analysis Endpoint
app.post("/analyze-file", upload.single("file"), async (req, res) => {
  try {
    const provider = req.headers['x-provider'] || 'openai';
    if (!req.file) return res.status(400).json({ result: "No file uploaded. Please select a file." });
    if (req.file.size > 2 * 1024 * 1024) return res.status(400).json({ result: "File too large (max 2MB)" });

    // Extract text by mime type
    async function extractText(file) {
      const mime = file.mimetype || "";
      if (mime.includes("pdf")) {
        const data = await pdfParse(file.buffer);
        return (data.text || "").slice(0, 20000);
      }
      if (mime.includes("word") || file.originalname.endsWith(".docx")) {
        const { value } = await mammoth.extractRawText({ buffer: file.buffer });
        return (value || "").slice(0, 20000);
      }
      if (mime.includes("csv") || file.originalname.endsWith(".csv")) {
        const text = file.buffer.toString("utf-8");
        return text.slice(0, 20000);
      }
      if (mime.includes("json") || file.originalname.endsWith(".json")) {
        const text = file.buffer.toString("utf-8");
        return text.slice(0, 20000);
      }
      if (mime.startsWith("image/")) {
        return "[image uploaded]";
      }
      // default: treat as text
      return file.buffer.toString("utf-8").slice(0, 20000);
    }

    const fileContent = await extractText(req.file);
    if (!fileContent || !fileContent.trim()) return res.status(400).json({ result: "File is empty. Please upload a non-empty file." });
    let result = "";
    if (provider === 'openai') {
      if (!openaiClient) return res.status(400).json({ result: "OpenAI not configured. Please set up your API key." });
      // If it was an image, use vision with image data URL
      if (req.file.mimetype && req.file.mimetype.startsWith("image/")) {
        const base64 = req.file.buffer.toString("base64");
        const execFn = () => openaiClient.chat.completions.create({
          model: activeModel || "gpt-4o-mini",
          messages: [
            { role: "system", content: "You are Prajna, a security analyst. Analyze the uploaded image and summarize any security-relevant content succinctly." },
            { role: "user", content: [{ type: "input_text", text: "Analyze this image for security-relevant content and provide a concise summary." }, { type: "input_image", image_url: `data:${req.file.mimetype};base64,${base64}` }] }
          ],
          max_tokens: 800
        });
        const response = await enqueueOpenAI(() => withBackoff(
          execFn,
          (e) => {
            const msg = (e && e.message) || '';
            const status = (e && e.status) || (e && e.response && e.response.status);
            return status === 429 || /rate|quota/i.test(msg);
          },
          3,
          800
        ));
        result = response.choices[0].message.content;
      } else {
        const execFn = () => openaiClient.chat.completions.create({
          model: activeModel || "gpt-4o-mini",
          messages: [
            { role: "system", content: "You are Prajna, a security analyst. Analyze the uploaded file and provide a summary or insights in plain text." },
            { role: "user", content: `File Content: ${fileContent.substring(0, 8000)}` }
          ],
          max_tokens: 800
        });
        const response = await enqueueOpenAI(() => withBackoff(
          execFn,
          (e) => {
            const msg = (e && e.message) || '';
            const status = (e && e.status) || (e && e.response && e.response.status);
            return status === 429 || /rate|quota/i.test(msg);
          },
          3,
          800
        ));
        result = response.choices[0].message.content;
      }
    } else if (provider === 'tgpt') {
      const analysisPrompt = `You are Prajna, a security analyst. Analyze the uploaded file content and provide a concise summary and key security insights in plain text. Content (truncated if large):\n\n${fileContent.substring(0, 8000)}`;
      const args = buildTgptArgs(null, {}, analysisPrompt);
      const { spawn } = require('child_process');
      result = await new Promise((resolve, reject) => {
        const child = spawn('sh', ['-c', `${config.tgpt.path} ${args.map(a => `"${a}"`).join(' ')}`], {
          stdio: ['pipe', 'pipe', 'pipe'],
          timeout: config.tgpt.timeoutMs,
          env: { ...process.env, TERM: 'dumb' }
        });
        let out = '';
        let err = '';
        child.stdout.on('data', d => { out += d.toString(); });
        child.stderr.on('data', d => { err += d.toString(); });
        child.on('close', code => {
          const text = (out || '').trim() || (err || '').trim() || '(No output from tgpt)';
          if (code !== 0 && !text) return reject(new Error(`tgpt exited with ${code}`));
          return resolve(text);
        });
        child.on('error', e => reject(e));
      });
    } else if (provider === 'gemini') {
      // Gemini API call here (pseudo-code, replace with real call)
      result = "Gemini file analysis coming soon.";
    } else if (provider === 'claude') {
      // Claude API call here (pseudo-code, replace with real call)
      result = "Claude file analysis coming soon.";
    } else {
      result = "Provider not supported.";
    }
    res.json({ result });
  } catch (error) {
    console.error("❌ File analysis error:", error.message);
    res.status(500).json({ result: `Error analyzing file: ${error.message}` });
  }
});

// --- Simple history persistence ---
app.get('/api/history', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf-8'));
    res.json(data);
  } catch (e) {
    res.json({ chats: [] });
  }
});

app.post('/api/history', (req, res) => {
  try {
    const { chats } = req.body;
    if (!Array.isArray(chats)) return res.status(400).json({ ok: false });
    fs.writeFileSync(HISTORY_FILE, JSON.stringify({ chats }, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

// --- Improved Splunk error handling ---
app.get("/test", async (req, res) => {
  try {
    const connectionOk = await testSplunkConnection();
    if (!connectionOk) {
      return res.status(500).json({ success: false, splunkConnected: false, error: "Splunk connection failed. Check .env and Splunk server status." });
    }
    const testQuery = `search index=${config.splunk.index} | head 10`;
    const logs = await executeSplunkSearch(testQuery);
    res.json({ success: true, splunkConnected: connectionOk, logsCount: logs.length, sampleLog: logs[0] || null });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Diagnostic endpoint for shell commands ---
app.get('/api/shell-test', (req, res) => {
  exec('ls -l /usr/local/bin', (error, stdout, stderr) => {
    res.json({
      command: 'ls -l /usr/local/bin',
      error: error ? error.message : null,
      stdout,
      stderr
    });
  });
});

// tgpt diagnostics - try multiple paths
app.get('/api/system/tgpt', (req, res) => {
  const pathsToTry = ["/usr/local/bin/tgpt","/usr/bin/tgpt","/home/ltsu/.local/bin/tgpt","/opt/tgpt/tgpt","tgpt"];
  let currentPathIndex = 0;
  function tryNextPath() {
    if (currentPathIndex >= pathsToTry.length) {
      return res.json({ path: "not found", ok: false, version: null, error: "tgpt not found in common paths", hint: "Install tgpt or set TGPT_PATH env variable" });
    }
    const currentPath = pathsToTry[currentPathIndex];
    exec(`"${currentPath}" --version`, { timeout: 5000 }, (error, stdout, stderr) => {
      const version = (stdout || "").trim() || (stderr || "").trim();
      if (version && version.length > 0) {
        return res.json({ path: currentPath, ok: true, version });
      }
      // If no version output, try next path
      currentPathIndex++;
      tryNextPath();
    });
  }
  tryNextPath();
});

// System Status
app.get("/api/system/status", async (req, res) => {
  const splunkOk = await testSplunkConnection();
  res.json({
    status: "ok",
    splunk: splunkOk,
    aiConfigured: !!openaiClient,
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  initializeAIClients();
});
