import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { z } from "zod";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const stateDir = path.join(process.env.LOCALAPPDATA || os.homedir(), "EnisV4LocalAgent", "state");
const configPath = path.join(stateDir, "config.json");
const tokenPath = path.join(stateDir, "admin-token.dpapi");
const installedScripts = path.join(process.env.LOCALAPPDATA || os.homedir(), "EnisV4LocalAgent", "app", "scripts");

function powershell() {
  const candidates = [
    process.env.ENIS_V4_POWERSHELL,
    "pwsh.exe",
    "powershell.exe",
    path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      execFileSync(candidate, ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"], { stdio: ["ignore", "pipe", "ignore"], timeout: 5000 });
      return candidate;
    } catch (_) {}
  }
  throw new Error("PowerShell was not found.");
}

function config() {
  if (process.env.ENIS_V4_DEVICE_ID && process.env.ENIS_V4_BRIDGE_URL) {
    return { deviceId: process.env.ENIS_V4_DEVICE_ID, bridgeUrl: process.env.ENIS_V4_BRIDGE_URL };
  }
  return JSON.parse(fs.readFileSync(configPath, "utf8").replace(/^\uFEFF/, ""));
}

function adminToken() {
  if (process.env.ENIS_V4_ADMIN_TOKEN) return process.env.ENIS_V4_ADMIN_TOKEN;
  const encrypted = fs.readFileSync(tokenPath, "utf8").trim().replace(/^\uFEFF/, "");
  const script = path.join(installedScripts, "dpapi-unprotect.ps1");
  return execFileSync(powershell(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-EncryptedValue", encrypted], { encoding: "utf8", timeout: 10000 }).trim();
}

async function requestJson(method, url, headers = {}, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 90000);
  try {
    const response = await fetch(url, {
      method,
      headers: { "content-type": "application/json", "user-agent": "enis-v4-mcp-gateway/0.1.0", ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal
    });
    const text = await response.text();
    const data = text ? JSON.parse(text.replace(/^\uFEFF/, "")) : {};
    if (!response.ok) throw new Error(`${method} ${url} failed: ${response.status} ${data.detail || response.statusText}`);
    return data;
  } finally {
    clearTimeout(timer);
  }
}

function bridge() { return config().bridgeUrl.replace(/\/+$/, ""); }
function auth() { return { "x-admin-token": adminToken() }; }
function textResult(value, isError = false) {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }], isError };
}

async function readJob(kind, timeoutSeconds = 90) {
  const c = config();
  const headers = auth();
  const job = await requestJson("POST", `${bridge()}/admin/jobs`, headers, {
    device_id: c.deviceId, kind, payload: {}, risk: "READ", ttl: Math.min(Math.max(timeoutSeconds, 10), 600)
  });
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    const status = await requestJson("GET", `${bridge()}/admin/jobs/${encodeURIComponent(job.job_id)}`, headers);
    if (status.state === "DONE") return status;
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  throw new Error(`Job ${job.job_id} did not finish within ${timeoutSeconds} seconds.`);
}

async function requestWrite(kind, payload = {}, timeoutSeconds = 90) {
  const c = config();
  const headers = auth();
  const job = await requestJson("POST", `${bridge()}/admin/jobs`, headers, {
    device_id: c.deviceId, kind, payload, risk: "WRITE", ttl: Math.min(Math.max(timeoutSeconds, 10), 600)
  });
  return { status: "APPROVAL_REQUIRED", job_id: job.job_id, kind, message: "Bu işlem için açık kullanıcı onayı gerekiyor. approve_action çağrısı olmadan çalıştırılmaz." };
}

function localDecision(jobId, kind, approved, reason) {
  const script = path.join(installedScripts, approved ? "Approve-LocalJob.ps1" : "Reject-LocalJob.ps1");
  const args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-JobId", jobId, "-Kind", kind];
  if (!approved && reason) args.push("-Reason", reason);
  const result = spawnSync(powershell(), args, { encoding: "utf8", timeout: 15000 });
  if (result.status !== 0) throw new Error(result.stderr || "Local approval decision failed.");
}

function registerTools(server) {
server.registerTool("list_devices", { description: "List paired Enis V4 Windows devices without exposing device secrets.", inputSchema: {} }, async () => { const c = config(); return textResult([{ deviceId: c.deviceId, hostname: os.hostname(), platform: os.platform(), bridgeUrl: c.bridgeUrl }]); });
server.registerTool("run_diagnostic", { description: "Run one READ diagnostic on the paired Windows device.", inputSchema: { kind: z.enum(["health", "self_test", "system_status", "disk_status", "process_list", "network_status"]), timeoutSeconds: z.number().int().min(10).max(600).optional() } }, async ({ kind, timeoutSeconds }) => textResult((await readJob(kind, timeoutSeconds || 90)).result));
server.registerTool("computer_status", { description: "Read current Windows system status through the Enis V4 agent.", inputSchema: { timeoutSeconds: z.number().int().min(10).max(600).optional() } }, async ({ timeoutSeconds }) => textResult((await readJob("system_status", timeoutSeconds || 90)).result));
server.registerTool("computer_disks", { description: "Read current Windows disk usage through the Enis V4 agent.", inputSchema: { timeoutSeconds: z.number().int().min(10).max(600).optional() } }, async ({ timeoutSeconds }) => textResult((await readJob("disk_status", timeoutSeconds || 90)).result));
server.registerTool("computer_processes", { description: "Read the top Windows processes by memory through the Enis V4 agent.", inputSchema: { timeoutSeconds: z.number().int().min(10).max(600).optional() } }, async ({ timeoutSeconds }) => textResult((await readJob("process_list", timeoutSeconds || 90)).result));
server.registerTool("computer_network", { description: "Read current Windows network interfaces through the Enis V4 agent.", inputSchema: { timeoutSeconds: z.number().int().min(10).max(600).optional() } }, async ({ timeoutSeconds }) => textResult((await readJob("network_status", timeoutSeconds || 90)).result));
if (process.env.ENIS_V4_MCP_READ_ONLY === "1") return;
server.registerTool("request_write_action", { description: "Create a signed WRITE job. It always returns APPROVAL_REQUIRED and never executes by itself.", inputSchema: { kind: z.string().min(1).max(64), payload: z.record(z.unknown()).optional(), timeoutSeconds: z.number().int().min(10).max(600).optional() } }, async ({ kind, payload, timeoutSeconds }) => textResult(await requestWrite(kind, payload || {}, timeoutSeconds || 90)));
server.registerTool("approve_action", { description: "Explicitly approve one pending WRITE job. Local approval is written before Bridge approval.", inputSchema: { jobId: z.string().uuid(), kind: z.string().min(1).max(64) } }, async ({ jobId, kind }) => { localDecision(jobId, kind, true); const result = await requestJson("POST", `${bridge()}/admin/jobs/${encodeURIComponent(jobId)}/approve`, auth(), {}); return textResult({ status: "APPROVED", job_id: jobId, bridge: result }); });
server.registerTool("reject_action", { description: "Explicitly reject one pending WRITE job and record the local decision.", inputSchema: { jobId: z.string().uuid(), kind: z.string().min(1).max(64), reason: z.string().max(500).optional() } }, async ({ jobId, kind, reason }) => { localDecision(jobId, kind, false, reason || "Rejected by user."); return textResult({ status: "REJECTED", job_id: jobId, kind, reason: reason || "Rejected by user." }); });
}

function createServer() {
  const server = new McpServer({ name: "enis-v4-windows", version: "0.1.0" });
  registerTools(server);
  return server;
}

async function serveHttp() {
  const app = createMcpExpressApp();
  const transports = {};
  const expectedToken = process.env.ENIS_V4_MCP_TOKEN;
  if (!expectedToken) throw new Error("ENIS_V4_MCP_TOKEN is required for HTTP mode.");
  app.use((req, res, next) => {
    if (req.path === "/health") return next();
    if (req.get("authorization") !== `Bearer ${expectedToken}`) return res.status(401).json({ ok: false, error: "unauthorized" });
    return next();
  });
  app.get("/health", (_req, res) => res.json({ ok: true, service: "enis-v4-mcp-gateway", transport: "streamable-http" }));
  app.post("/mcp", async (req, res) => {
    try {
      const sessionId = req.headers["mcp-session-id"];
      let transport = sessionId ? transports[sessionId] : undefined;
      if (!transport && !sessionId && isInitializeRequest(req.body)) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
          onsessioninitialized: (id) => { transports[id] = transport; }
        });
        const server = createServer();
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      }
      if (!transport) return res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "Missing or invalid MCP session." }, id: null });
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  });
  app.get("/mcp", (_req, res) => res.status(405).set("Allow", "POST").send("Method Not Allowed"));
  app.delete("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    const transport = sessionId ? transports[sessionId] : undefined;
    if (!transport) return res.status(404).send("Session not found");
    await transport.handleRequest(req, res);
    delete transports[sessionId];
  });
  const port = Number(process.env.PORT || 3000);
  app.listen(port, "0.0.0.0", () => console.error(`Enis V4 MCP HTTP listening on ${port}`));
}

if (process.env.ENIS_V4_MCP_HTTP === "1") {
  await serveHttp();
} else {
  const transport = new StdioServerTransport();
  await createServer().connect(transport);
}
