import { normalizeUpload } from "../api/client.js";

function parseArea(id) {
  const value = document.getElementById(id)?.value?.trim();
  if (!value) return [];
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) {
    throw new Error(`${id} must be a JSON array`);
  }
  return parsed;
}

export async function normalizeFromUpload() {
  const seeds = parseArea("upload-seeds");
  const attacks = parseArea("upload-attacks");
  const session_events = parseArea("upload-events");
  return normalizeUpload({ seeds, attacks, session_events });
}
