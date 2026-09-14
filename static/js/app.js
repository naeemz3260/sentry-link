const GAUGE_CIRCUMFERENCE = 377; // 2 * PI * r(60)

const els = {
  form: document.getElementById("scan-form"),
  input: document.getElementById("url-input"),
  scanBtn: document.getElementById("scan-btn"),
  loading: document.getElementById("loading"),
  loadingText: document.getElementById("loading-text"),
  errorBox: document.getElementById("error-box"),
  results: document.getElementById("results"),
  gaugeFill: document.getElementById("gauge-fill"),
  scoreNumber: document.getElementById("score-number"),
  gradeBadge: document.getElementById("grade-badge"),
  classificationPill: document.getElementById("classification-pill"),
  tagline: document.getElementById("tagline"),
  metaSubmitted: document.getElementById("meta-submitted"),
  metaFinal: document.getElementById("meta-final"),
  metaChannels: document.getElementById("meta-channels"),
  metaTime: document.getElementById("meta-time"),
  channelsList: document.getElementById("channels-list"),
  recsList: document.getElementById("recs-list"),
  exportBtn: document.getElementById("export-btn"),
  navLinks: document.querySelectorAll(".nav-link"),
  views: document.querySelectorAll(".view"),
  historyEmpty: document.getElementById("history-empty"),
  historyTable: document.getElementById("history-table"),
  historyBody: document.getElementById("history-body"),
  clearHistoryBtn: document.getElementById("clear-history-btn"),
};

let currentScanId = null;

const LOADING_STEPS = [
  "Validating URL syntax…",
  "Checking HTTPS & certificate…",
  "Looking up domain age…",
  "Scanning for phishing indicators…",
  "Tracing redirects & headers…",
  "Calculating risk score…",
];

function gradeColor(grade) {
  if (grade === "A" || grade === "B") return "var(--teal)";
  if (grade === "C") return "var(--amber)";
  return "var(--red)";
}

function statusClass(status) {
  return status === "pass" ? "pass" : status === "warn" ? "warn" : "fail";
}

function setLoading(active) {
  els.loading.classList.toggle("hidden", !active);
  els.scanBtn.disabled = active;
  if (active) {
    let i = 0;
    els.loadingText.textContent = LOADING_STEPS[0];
    clearInterval(window.__loadingTimer);
    window.__loadingTimer = setInterval(() => {
      i = (i + 1) % LOADING_STEPS.length;
      els.loadingText.textContent = LOADING_STEPS[i];
    }, 650);
  } else {
    clearInterval(window.__loadingTimer);
  }
}

function showError(message) {
  els.errorBox.textContent = message;
  els.errorBox.classList.remove("hidden");
}

function clearError() {
  els.errorBox.classList.add("hidden");
  els.errorBox.textContent = "";
}

function renderResult(result) {
  currentScanId = result.id ?? null;
  els.results.classList.remove("hidden");

  const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * result.score) / 100;
  const color = gradeColor(result.grade);
  els.gaugeFill.style.stroke = color;
  requestAnimationFrame(() => {
    els.gaugeFill.style.strokeDashoffset = offset;
  });
  els.scoreNumber.textContent = result.score;
  els.scoreNumber.style.color = color;

  els.gradeBadge.textContent = result.grade;
  els.gradeBadge.style.borderColor = color;
  els.gradeBadge.style.color = color;
  els.classificationPill.textContent = result.classification;
  els.tagline.textContent = result.tagline;

  els.metaSubmitted.textContent = result.submitted_url;
  els.metaFinal.textContent = result.final_url || result.normalized_url;
  els.metaChannels.textContent = `${result.channel_count} channels evaluated`;
  els.metaTime.textContent = `${result.scan_time_ms} ms`;

  els.channelsList.innerHTML = "";
  result.channels.forEach((c) => {
    const pct = Math.round((c.points / c.max_points) * 100);
    const row = document.createElement("div");
    row.className = "channel-row";
    row.innerHTML = `
      <div class="channel-head">
        <span class="channel-dot ${statusClass(c.status)}"></span>
        <span class="channel-name">${c.name}</span>
        <span class="channel-score">${c.points}/${c.max_points}</span>
        <span class="channel-caret">▸</span>
      </div>
      <div class="channel-meter"><div class="channel-meter-fill ${statusClass(c.status)}" style="width:${pct}%"></div></div>
      <ul class="channel-details">${c.details.map((d) => `<li>${escapeHtml(d)}</li>`).join("")}</ul>
    `;
    row.addEventListener("click", () => row.classList.toggle("open"));
    els.channelsList.appendChild(row);
  });

  els.recsList.innerHTML = "";
  result.recommendations.forEach((r) => {
    const li = document.createElement("li");
    li.innerHTML = `<strong>${escapeHtml(r.channel)}</strong>${escapeHtml(r.recommendation)}`;
    els.recsList.appendChild(li);
  });

  els.results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

els.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = els.input.value.trim();
  if (!url) return;

  clearError();
  els.results.classList.add("hidden");
  setLoading(true);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (!res.ok) {
      showError(data.error || "Something went wrong while scanning.");
      return;
    }
    renderResult(data);
  } catch (err) {
    showError("Could not reach the scanning service. Is the server running?");
  } finally {
    setLoading(false);
  }
});

els.exportBtn.addEventListener("click", () => {
  if (!currentScanId) return;
  window.open(`/api/history/${currentScanId}/report`, "_blank");
});

/* ---------- navigation ---------- */
els.navLinks.forEach((btn) => {
  btn.addEventListener("click", () => {
    els.navLinks.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const view = btn.dataset.view;
    els.views.forEach((v) => v.classList.toggle("active", v.id === `view-${view}`));
    if (view === "history") loadHistory();
  });
});

/* ---------- history ---------- */
async function loadHistory() {
  try {
    const res = await fetch("/api/history");
    const rows = await res.json();
    if (!rows.length) {
      els.historyEmpty.classList.remove("hidden");
      els.historyTable.classList.add("hidden");
      return;
    }
    els.historyEmpty.classList.add("hidden");
    els.historyTable.classList.remove("hidden");
    els.historyBody.innerHTML = "";
    rows.forEach((r) => {
      const tr = document.createElement("tr");
      tr.className = "hist-row";
      const when = new Date(r.created_at).toLocaleString();
      tr.innerHTML = `
        <td><span class="hist-url">${escapeHtml(r.submitted_url)}</span></td>
        <td>${r.score}</td>
        <td class="hist-grade" style="color:${gradeColor(r.grade)}">${r.grade}</td>
        <td>${escapeHtml(r.classification)}</td>
        <td>${escapeHtml(when)}</td>
        <td><button class="hist-del" title="Delete" data-id="${r.id}">✕</button></td>
      `;
      tr.addEventListener("click", (e) => {
        if (e.target.closest(".hist-del")) return;
        openHistoryScan(r.id);
      });
      tr.querySelector(".hist-del").addEventListener("click", async (e) => {
        e.stopPropagation();
        await fetch(`/api/history/${r.id}`, { method: "DELETE" });
        loadHistory();
      });
      els.historyBody.appendChild(tr);
    });
  } catch (err) {
    els.historyEmpty.textContent = "Could not load history.";
    els.historyEmpty.classList.remove("hidden");
  }
}

async function openHistoryScan(id) {
  const res = await fetch(`/api/history/${id}`);
  const data = await res.json();
  if (!res.ok) return;
  els.navLinks.forEach((b) => b.classList.toggle("active", b.dataset.view === "scan"));
  els.views.forEach((v) => v.classList.toggle("active", v.id === "view-scan"));
  els.input.value = data.result.submitted_url;
  renderResult({ ...data.result, id: data.id });
}

els.clearHistoryBtn.addEventListener("click", async () => {
  if (!confirm("Clear all scan history? This cannot be undone.")) return;
  await fetch("/api/history", { method: "DELETE" });
  loadHistory();
});
