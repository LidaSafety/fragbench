async function req(path, options = {}) {
  const resp = await fetch(path, options);
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || `request failed: ${path}`);
  }
  return data;
}

export async function fetchRuns() {
  const payload = await req("/api/runs");
  return payload.runs || [];
}

export async function fetchLatestRun() {
  return req("/api/run/latest");
}

export async function fetchRunById(runId) {
  return req(`/api/run/${encodeURIComponent(runId)}`);
}

export async function normalizeUpload(payload) {
  return req("/api/normalize_upload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
