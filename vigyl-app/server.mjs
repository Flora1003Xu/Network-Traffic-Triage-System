import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, "data");
const reportsFile = process.env.REPORTS_FILE || path.join(dataDir, "reports.json");
const port = Number.parseInt(process.env.PORT || "3001", 10);
const host = process.env.HOST || "127.0.0.1";

function json(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  response.end(JSON.stringify(payload, null, 2));
}

async function ensureStore() {
  await mkdir(path.dirname(reportsFile), { recursive: true });
  try {
    await readFile(reportsFile, "utf8");
  } catch {
    await writeStore({ reports: [], updatedAt: null });
  }
}

async function readStore() {
  await ensureStore();
  const content = await readFile(reportsFile, "utf8");
  try {
    const parsed = JSON.parse(content);
    return {
      reports: Array.isArray(parsed.reports) ? parsed.reports : [],
      updatedAt: parsed.updatedAt || null,
    };
  } catch {
    return { reports: [], updatedAt: null };
  }
}

async function writeStore(store) {
  await mkdir(path.dirname(reportsFile), { recursive: true });
  await writeFile(reportsFile, JSON.stringify(store, null, 2), 'utf8');
}

function toArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.reports)) return payload.reports;
  if (payload?.incident) return [payload.incident];
  return payload ? [payload] : [];
}

function pickTimestamp(report) {
  const candidate =
    report.timestamp ||
    report.generated_at ||
    report.created_at ||
    report.received_at ||
    report.savedPath?.match(/(\d{4}-\d{2}-\d{2}T[\d-]+Z)/)?.[1]?.replace(/-/g, (m, o) => o > 18 ? ':' : m);
  const parsed = new Date(candidate || Date.now());
  return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

function mergeReports(existingReports, incomingReports) {
  const merged = new Map(
    existingReports.map((report) => [
      report.id ||
      report.incidentId ||
      report.incident_id ||
      report.report_id ||
      JSON.stringify(report),
      report
    ])
  );

  for (const report of incomingReports) {
    const timestamp = pickTimestamp(report);
    const key =
      report.id ||
      report.incidentId ||
      report.incident_id ||
      report.report_id ||
      `${timestamp}-${Math.random().toString(36).slice(2, 10)}`;

    merged.set(key, {
      ...report,
      id: key,
      received_at: report.received_at || new Date().toISOString(),
      timestamp,
    });
  }

  return Array.from(merged.values()).sort(
    (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
  );
}

async function readJsonBody(request) {
  const chunks = [];
  let total = 0;

  for await (const chunk of request) {
    total += chunk.length;
    if (total > 1024 * 1024) {
      throw new Error("Payload too large");
    }
    chunks.push(chunk);
  }

  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

const server = createServer(async (request, response) => {
  if (!request.url) {
    json(response, 400, { error: "Missing request URL" });
    return;
  }

  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);

  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    });
    response.end();
    return;
  }

  if (request.method === "GET" && url.pathname === "/health") {
    const store = await readStore();
    json(response, 200, { ok: true, reports: store.reports.length, updatedAt: store.updatedAt });
    return;
  }

  if (request.method === "GET" && url.pathname === "/api/reports") {
    const store = await readStore();
    json(response, 200, { reports: store.reports, count: store.reports.length, updatedAt: store.updatedAt });
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/reports") {
    try {
      const payload = await readJsonBody(request);
      const incomingReports = toArray(payload);

      if (incomingReports.length === 0) {
        json(response, 400, { error: "Request body must include a report object or a reports array" });
        return;
      }

      const store = await readStore();
      const reports = mergeReports(store.reports, incomingReports);
      const updatedAt = new Date().toISOString();
      await writeStore({ reports, updatedAt });

      json(response, 201, {
        ok: true,
        received: incomingReports.length,
        count: reports.length,
        updatedAt,
      });
    } catch (error) {
      const statusCode = error instanceof SyntaxError ? 400 : 500;
      json(response, statusCode, { error: error.message || "Failed to process request" });
    }
    return;
  }

  json(response, 404, { error: "Not found" });
});

server.on("error", (error) => {
  console.error(`ViGYL reports API failed to start on http://${host}:${port}`);
  console.error(error);
  process.exitCode = 1;
});

server.listen(port, host, () => {
  console.log(`ViGYL reports API listening on http://${host}:${port}`);
});
