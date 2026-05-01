async function req(path, options = {}) {
  const resp = await fetch(path, options);
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || `request failed: ${path}`);
  }
  return data;
}

function withFragments(path, fragmentsPath) {
  if (!fragmentsPath) return path;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}fragments=${encodeURIComponent(fragmentsPath)}`;
}

export async function fetchRuns({ fragmentsPath } = {}) {
  const payload = await req(withFragments("/api/runs", fragmentsPath));
  return payload.runs || [];
}

export async function fetchLatestRun({ fragmentsPath } = {}) {
  return req(withFragments("/api/run/latest", fragmentsPath));
}

export async function fetchRunById(runId, { fragmentsPath } = {}) {
  return req(withFragments(`/api/run/${encodeURIComponent(runId)}`, fragmentsPath));
}

export async function fetchFragmentsFiles() {
  const payload = await req("/api/fragments-files");
  return payload.files || [];
}

export async function normalizeUpload(payload) {
  return req("/api/normalize_upload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
