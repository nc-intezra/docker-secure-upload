// Upload page. Speaks the tus 1.0.0 protocol (creation + termination) to
// /api/v1/uploads/. No innerHTML anywhere: the page runs under Trusted Types.
"use strict";

(function () {
  const meta = (n) => document.querySelector(`meta[name="${n}"]`).content;
  const CSRF = meta("csrf-token");
  const CHUNK = Number(meta("chunk-size"));
  const MAX_FILE = Number(meta("max-file-size"));
  const MAX_FILES = Number(meta("max-batch-files"));
  const UPLOADS = "/api/v1/uploads/";
  const USER_RE = /^[a-z][a-z0-9._-]{0,31}$/;
  const PARALLEL = 2;
  const MAX_RETRIES = 30;

  const $ = (id) => document.getElementById(id);
  const userInput = $("username");
  const userError = $("username-error");
  const drop = $("dropzone");
  const fileInput = $("file-input");
  const list = $("file-list");
  const uploadBtn = $("upload-btn");
  const clearBtn = $("clear-btn");
  const statusEl = $("status");
  const prefixBox = $("prefix-names");

  /** @type {{file: File, key: string, url: string|null, id: string|null, state: string, sha256: string, sent: number, cancelled: boolean, xhr: XMLHttpRequest|null, row: HTMLElement}[]} */
  let entries = [];
  let busy = false;

  const LABELS = {
    queued: "Ready",
    uploading: "Uploading",
    waiting: "Connection lost, retrying",
    limited: "Waiting for your earlier uploads to finish",
    scanning: "Scanning for viruses",
    sent: "Sent to the diode",
    sent_unscanned: "Sent; too large to scan fully",
    blocked: "Blocked by antivirus",
    held: "Held for administrator review",
    cancelled: "Cancelled",
    failed: "Failed",
  };
  const FINAL = new Set(["sent", "sent_unscanned", "blocked", "held", "cancelled", "failed"]);

  // ---------- username ----------
  try { userInput.value = localStorage.getItem("username") || ""; } catch (_) { /* storage blocked */ }
  function checkUser(show) {
    const v = userInput.value.trim().toLowerCase();
    const ok = USER_RE.test(v);
    userError.hidden = ok || !show;
    userError.textContent = ok ? "" : "Start with a letter; use only a-z, 0-9, '.', '_' or '-' (up to 32).";
    userInput.setAttribute("aria-invalid", ok ? "false" : "true");
    return ok ? v : null;
  }
  userInput.addEventListener("input", () => { checkUser(false); refreshButtons(); });
  userInput.addEventListener("blur", () => checkUser(userInput.value !== ""));

  // ---------- adding files ----------
  function human(n) {
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function addFiles(files) {
    if (busy) return;
    let skipped = 0;
    for (const f of files) {
      const key = `${f.name}|${f.size}|${f.lastModified}`;
      if (entries.some((e) => e.key === key)) continue;
      if (f.size > MAX_FILE) { skipped++; continue; }
      if (entries.length >= MAX_FILES) { skipped++; continue; }
      const entry = { file: f, key, url: null, id: null, state: "queued", sha256: "", sent: 0, cancelled: false, xhr: null, row: null };
      entry.row = buildRow(entry);
      list.appendChild(entry.row);
      entries.push(entry);
    }
    say(skipped ? `${skipped} file(s) skipped: too large, duplicate or over the ${MAX_FILES}-file limit.` : "");
    refreshButtons();
  }

  function buildRow(entry) {
    const li = el("li", "file");
    const top = el("div", "file-top");
    top.appendChild(el("span", "file-name", entry.file.name));
    top.appendChild(el("span", "file-size", human(entry.file.size)));
    const btn = el("button", "icon-btn", "Remove");
    btn.type = "button";
    btn.setAttribute("aria-label", `Remove ${entry.file.name}`);
    btn.addEventListener("click", () => onRowButton(entry));
    top.appendChild(btn);
    li.appendChild(top);
    const bar = el("progress", "bar");
    bar.max = 100; bar.value = 0;
    li.appendChild(bar);
    li.appendChild(el("p", "file-state", LABELS.queued));
    const sentAs = el("p", "file-hash");
    sentAs.hidden = true;
    li.appendChild(sentAs);
    const hash = el("p", "file-hash");
    hash.hidden = true;
    li.appendChild(hash);
    entry.parts = { btn, bar, state: li.querySelector(".file-state"), sentAs, hash };
    return li;
  }

  function render(entry, note) {
    const p = entry.parts;
    const pct = entry.file.size ? Math.floor((entry.sent / entry.file.size) * 100) : 100;
    p.bar.value = entry.state === "uploading" || entry.state === "waiting" || entry.state === "limited" ? pct : (FINAL.has(entry.state) || entry.state === "scanning" ? 100 : 0);
    let label = LABELS[entry.state] || entry.state;
    if (entry.state === "uploading") label += ` ${pct}%`;
    if (note) label += `: ${note}`;
    p.state.textContent = label;
    entry.row.dataset.state = entry.state;
    if (entry.sentAs && (entry.state === "sent" || entry.state === "sent_unscanned")) {
      p.sentAs.hidden = false;
      p.sentAs.textContent = `Arrives as: ${entry.sentAs}`;
    }
    if (entry.sha256) {
      p.hash.hidden = false;
      p.hash.textContent = "";
      p.hash.appendChild(el("span", "hash-label", "SHA-256 "));
      p.hash.appendChild(el("code", "", entry.sha256));
    }
    if (!busy) p.btn.textContent = "Remove";
    else if (["uploading", "waiting", "limited", "queued"].includes(entry.state)) p.btn.textContent = "Cancel";
    else p.btn.hidden = true;
  }

  function onRowButton(entry) {
    if (!busy) {
      entries = entries.filter((e) => e !== entry);
      entry.row.remove();
      refreshButtons();
      return;
    }
    if (FINAL.has(entry.state) || entry.state === "scanning") return;
    entry.cancelled = true;
    if (entry.xhr) entry.xhr.abort();
  }

  drop.addEventListener("click", () => fileInput.click());
  drop.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", () => { addFiles(fileInput.files); fileInput.value = ""; });
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (ev) => {
    ev.preventDefault();
    if (!busy) drop.classList.add("over");
  }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, () => drop.classList.remove("over")));
  drop.addEventListener("drop", (ev) => {
    ev.preventDefault();
    const files = [];
    let folders = 0;
    for (const item of ev.dataTransfer.items || []) {
      const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
      if (entry && entry.isDirectory) { folders++; continue; }
      const f = item.getAsFile();
      if (f) files.push(f);
    }
    addFiles(files);
    if (folders) say(`${folders} folder(s) skipped. Drop the files inside them, or zip the folder first.`);
  });
  // Stop a stray drop elsewhere from navigating away from the page.
  window.addEventListener("dragover", (ev) => ev.preventDefault());
  window.addEventListener("drop", (ev) => ev.preventDefault());

  clearBtn.addEventListener("click", () => {
    if (busy) return;
    entries = [];
    list.textContent = "";
    say("");
    refreshButtons();
  });

  function refreshButtons() {
    uploadBtn.disabled = busy || entries.length === 0 || !checkUser(false) || entries.every((e) => FINAL.has(e.state));
    clearBtn.disabled = busy || entries.length === 0;
    userInput.disabled = busy;
    prefixBox.disabled = busy;
    drop.setAttribute("aria-disabled", busy ? "true" : "false");
  }

  function say(msg) { statusEl.textContent = msg; }

  // ---------- protocol ----------
  function b64(s) {
    const bytes = new TextEncoder().encode(s);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }

  async function api(method, url, body) {
    const res = await fetch(url, {
      method,
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty body */ }
    if (!res.ok) throw new Error((data && data.message) || `HTTP ${res.status}`);
    return data;
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  class Fatal extends Error {}

  function tusRequest(method, url, headers, body, onProgress, entry) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      entry.xhr = xhr;
      xhr.open(method, url);
      xhr.setRequestHeader("Tus-Resumable", "1.0.0");
      xhr.setRequestHeader("X-CSRF-Token", CSRF);
      for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
      if (onProgress) xhr.upload.onprogress = (ev) => onProgress(ev.loaded);
      xhr.onload = () => { entry.xhr = null; resolve(xhr); };
      xhr.onerror = () => { entry.xhr = null; reject(new Error("network error")); };
      xhr.onabort = () => { entry.xhr = null; reject(new Error("aborted")); };
      xhr.send(body);
    });
  }

  async function createUpload(entry, batchId) {
    const meta = `batch_id ${b64(batchId)},filename ${b64(entry.file.name)}`;
    let xhr;
    // 429: this computer already has too much in flight. Wait for earlier
    // uploads to finish rather than fail, for up to about half an hour.
    for (let tries = 0; ; tries++) {
      xhr = await tusRequest("POST", UPLOADS, { "Upload-Length": String(entry.file.size), "Upload-Metadata": meta }, null, null, entry);
      if (xhr.status !== 429 || tries >= 30) break;
      if (entry.cancelled) throw new Error("aborted");
      entry.state = "limited";
      render(entry);
      const after = Number(xhr.getResponseHeader("Retry-After")) || 60;
      await sleep(Math.min(120, Math.max(5, after)) * 1000);
      if (entry.cancelled) throw new Error("aborted");
    }
    if (xhr.status !== 201) throw new Fatal(xhr.responseText.trim() || `HTTP ${xhr.status}`);
    entry.state = "uploading";
    render(entry);
    const loc = xhr.getResponseHeader("Location") || "";
    if (!loc.startsWith(UPLOADS)) throw new Fatal("server returned an unexpected location");
    entry.url = loc;
    entry.id = loc.slice(UPLOADS.length);
  }

  async function currentOffset(entry) {
    const xhr = await tusRequest("HEAD", entry.url, {}, null, null, entry);
    if (xhr.status !== 200) throw new Fatal(`HTTP ${xhr.status}`);
    return Number(xhr.getResponseHeader("Upload-Offset"));
  }

  async function sendFile(entry, batchId) {
    entry.state = "uploading";
    render(entry);
    await createUpload(entry, batchId);
    let offset = 0;
    let failures = 0;
    while (offset < entry.file.size) {
      if (entry.cancelled) throw new Error("aborted");
      const chunk = entry.file.slice(offset, Math.min(offset + CHUNK, entry.file.size));
      try {
        const xhr = await tusRequest("PATCH", entry.url,
          { "Content-Type": "application/offset+octet-stream", "Upload-Offset": String(offset) },
          chunk, (loaded) => { entry.sent = offset + loaded; render(entry); }, entry);
        if (xhr.status === 204) {
          offset = Number(xhr.getResponseHeader("Upload-Offset"));
          entry.sent = offset;
          failures = 0;
          entry.state = "uploading";
          render(entry);
          continue;
        }
        if (xhr.status === 409 || xhr.status === 423 || xhr.status >= 500) {
          throw new Error(`HTTP ${xhr.status}`);
        }
        throw new Fatal(xhr.responseText.trim() || `HTTP ${xhr.status}`);
      } catch (err) {
        if (err instanceof Fatal || entry.cancelled) throw err;
        failures++;
        if (failures > MAX_RETRIES) throw new Fatal("gave up after repeated connection failures");
        entry.state = "waiting";
        render(entry);
        await sleep(Math.min(30000, 1000 * 2 ** Math.min(failures, 5)));
        try { offset = await currentOffset(entry); } catch (e) { if (e instanceof Fatal) throw e; }
      }
    }
    entry.state = "scanning";
    entry.sent = entry.file.size;
    render(entry);
  }

  async function cancelOnServer(entry) {
    if (!entry.url) return;
    try { await tusRequest("DELETE", entry.url, {}, null, null, entry); } catch (_) { /* best effort */ }
  }

  async function worker(queue, batchId) {
    while (queue.length) {
      const entry = queue.shift();
      try {
        if (entry.cancelled) throw new Error("aborted");
        await sendFile(entry, batchId);
      } catch (err) {
        if (entry.cancelled) {
          await cancelOnServer(entry);
          entry.state = "cancelled";
          render(entry);
        } else {
          // Release the server-side upload so the batch can close.
          await cancelOnServer(entry);
          entry.state = "failed";
          render(entry, err.message);
        }
      }
    }
  }

  async function poll(batchId) {
    for (;;) {
      let data;
      try { data = await api("GET", `/api/v1/batches/${encodeURIComponent(batchId)}`); } catch (_) { await sleep(5000); continue; }
      const byId = new Map(data.files.map((f) => [f.id, f]));
      for (const e of entries) {
        const f = e.id && byId.get(e.id);
        if (!f || e.state === "failed") continue;
        if (f.state !== "uploading") {
          e.state = f.state;
          if (f.sha256) e.sha256 = f.sha256;
          if (f.sent_as) e.sentAs = f.sent_as;
          render(e);
        }
      }
      if (entries.every((e) => FINAL.has(e.state))) return data;
      await sleep(2000);
    }
  }

  uploadBtn.addEventListener("click", async () => {
    const user = checkUser(true);
    const todo = entries.filter((e) => !FINAL.has(e.state));
    if (!user || todo.length === 0) return;
    try { localStorage.setItem("username", user); } catch (_) { /* storage blocked */ }
    busy = true;
    refreshButtons();
    todo.forEach((e) => render(e));
    say("Starting…");
    let batch;
    try {
      batch = await api("POST", "/api/v1/batches", { username: user, file_count: todo.length, prefix_names: prefixBox.checked });
    } catch (err) {
      busy = false;
      refreshButtons();
      say(`Could not start: ${err.message}`);
      return;
    }
    say(`Batch ${batch.batch_id}: uploading. Keep this page open.`);
    const queue = todo.slice();
    const polling = poll(batch.batch_id);
    await Promise.all(Array.from({ length: Math.min(PARALLEL, queue.length) }, () => worker(queue, batch.batch_id)));
    say("All files received; waiting for virus scan results…");
    await polling;
    busy = false;
    refreshButtons();
    const counts = {};
    todo.forEach((e) => { counts[e.state] = (counts[e.state] || 0) + 1; });
    const parts = Object.entries(counts).map(([s, n]) => `${n} ${LABELS[s].toLowerCase()}`);
    say(`Batch ${batch.batch_id} finished: ${parts.join(", ")}.`);
    todo.forEach((e) => render(e));
  });

  window.addEventListener("beforeunload", (ev) => {
    if (busy) { ev.preventDefault(); ev.returnValue = ""; }
  });

  checkUser(false);
  refreshButtons();
})();
