"use strict";

const state = { session: "", open: new Set(), seen: new Set(), first: true, actions: [], alertSeq: null, sessionKey: "" };
const post = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
const $ = (id) => document.getElementById(id);

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const time = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
};
const q = () => (state.session ? `?session=${encodeURIComponent(state.session)}` : "");

function kind(a) {
  if (a.status === "awaiting approval") return "pending";
  if (a.status === "blocked" || a.status === "denied") return "block";
  if (a.decision === "require_approval") return "approve";
  if (a.decision === "restrict") return "restrict";
  return "allow";
}

function outcome(a) {
  switch (a.status) {
    case "blocked": return ["block", "Blocked"];
    case "denied": return ["block", a.approval?.status === "expired" ? "Approval timed out" : "Denied by reviewer"];
    case "failed": return ["neutral", "Tool error"];
    case "awaiting approval": return ["approve", "Waiting for approval"];
    case "succeeded":
      if (a.decision === "require_approval") return ["approve", `Approved by ${a.approval?.reviewer || "reviewer"}`];
      if (a.decision === "restrict") return ["restrict", a.redactions ? `Restricted, ${a.redactions} redacted` : "Restricted"];
      return ["allow", "Allowed"];
    default: return ["neutral", "Running"];
  }
}

function riskCell(r) {
  const s = r?.score ?? 0;
  const lvl = s >= 70 ? "high" : s >= 40 ? "mid" : "";
  return `<div class="risk ${lvl}"><span class="risk-bar"><i style="width:${s}%"></i></span>${s}</div>`;
}

function detailHtml(a) {
  const factors = (a.risk?.factors || []).map((f) => `<div class="factor"><span>${esc(f.reason)}</span><b>+${f.points}</b></div>`).join("");
  const reasons = (a.reasons || []).map((r) => `<li>${esc(r)}</li>`).join("");
  const findings = [...(a.findings || []), ...(a.after_findings || [])]
    .filter((f) => f.severity !== "info" || f.decision !== "allow" || f.grant)
    .map((f) => `<li class="finding ${f.severity}">${esc(f.guard.replace(/_/g, " "))}: ${esc(f.reason)}</li>`).join("");
  const guardHtml = findings ? `<h4>Guard checks</h4><ul>${findings}</ul>` : "";
  const approval = a.approval ? `<h4>Approval</h4><p>${esc(a.approval.status)}${a.approval.reviewer ? " by " + esc(a.approval.reviewer) : ""}${a.approval.note ? ": " + esc(a.approval.note) : ""}</p>` : "";
  const result = a.result_preview ? `<h4>What the tool returned (as recorded)</h4><pre>${esc(a.result_preview)}</pre>` : a.message ? `<h4>Message to agent</h4><p>${esc(a.message)}</p>` : "";
  return `<div class="detail-grid">
    <div>
      <h4>Stated purpose</h4><p>${a.purpose ? esc(a.purpose) : "<em>None given</em>"}</p>
      <h4>Why Heimdall decided this</h4><ul>${reasons}</ul>
      ${guardHtml}
      ${approval}
    </div>
    <div><h4>Risk score ${a.risk?.score ?? 0}</h4>${factors}<p class="meta" style="margin-top:8px">Action ${esc(a.action_id)} in session ${esc(a.session_id)}</p></div>
    <div><h4>Arguments</h4><pre>${esc(JSON.stringify(a.arguments ?? {}, null, 2))}</pre>${result}</div>
  </div>`;
}

function renderBridge(actions) {
  const el = $("bridge");
  if (!actions.length) {
    el.innerHTML = `<p class="empty">No agent has crossed yet. Start a demo with <code>heimdall demo</code>.</p>`;
    return;
  }
  const recent = actions.slice(-120);
  const max = Math.max(...recent.map((a) => a.risk?.score ?? 0), 1);
  el.innerHTML = recent.map((a) => {
    const h = 22 + Math.round(((a.risk?.score ?? 0) / Math.max(max, 60)) * 54);
    const [, label] = outcome(a);
    return `<button class="seg ${kind(a)}" style="height:${h}px" data-id="${esc(a.action_id)}"
      title="${esc(a.tool)}: ${esc(label)} (risk ${a.risk?.score ?? 0})" aria-label="${esc(a.tool)}, ${esc(label)}"></button>`;
  }).join("");
  el.scrollLeft = el.scrollWidth;
  $("bridge-title").textContent = state.session ? "The bridge, this session" : "The bridge";
}

function renderFeed(actions) {
  const onlyFlagged = $("only-flagged").checked;
  const rows = actions.filter((a) => !onlyFlagged || kind(a) !== "allow").slice().reverse();
  if (!rows.length) {
    $("feed").innerHTML = `<tr><td colspan="5" class="empty" style="padding:20px">Nothing to show yet.</td></tr>`;
    return;
  }
  $("feed").innerHTML = rows.map((a) => {
    const [cls, label] = outcome(a);
    const open = state.open.has(a.action_id);
    const fresh = !state.first && !state.seen.has(a.action_id);
    return `<tr class="row${open ? " open" : ""}${fresh ? " flash" : ""}" data-id="${esc(a.action_id)}" tabindex="0" aria-expanded="${open}">
        <td class="time">${time(a.ts)}</td>
        <td class="agent">${esc(a.agent)}</td>
        <td><span class="tool">${esc(a.tool)}</span><span class="target">${esc(a.target)}</span></td>
        <td>${riskCell(a.risk)}</td>
        <td><span class="pill ${cls}">${esc(label)}</span></td>
      </tr>${open ? `<tr class="detail"><td colspan="5">${detailHtml(a)}</td></tr>` : ""}`;
  }).join("");
  actions.forEach((a) => state.seen.add(a.action_id));
}

function renderStats(o) {
  const items = [
    ["Actions seen", o.actions],
    ["Allowed through", o.allowed],
    ["Restricted", o.restricted],
    ["Blocked or denied", o.blocked, o.blocked > 0],
    ["Critical alerts", o.critical_alerts, o.critical_alerts > 0],
    ["Deceptive reports", o.deceptive_reports, o.deceptive_reports > 0],
    ["Quarantined sessions", o.quarantined, o.quarantined > 0],
  ];
  $("stats").innerHTML = items.map(([k, v, warn]) => `<div class="${warn ? "warn" : ""}"><dt>${k}</dt><dd>${v}</dd></div>`).join("");

  const c = o.chain, btn = $("chain");
  btn.className = "chain " + (c.ok ? "ok" : "bad");
  btn.textContent = c.ok ? `Audit trail intact (${c.entries} entries)` : `Audit trail broken (${c.problems.length} problem${c.problems.length === 1 ? "" : "s"})`;
  $("chain-detail").innerHTML = `
    <p>${c.ok ? "Every entry matches its hash and links to the one before it." : "Some entries were changed, deleted or reordered after they were written."}</p>
    <p class="meta">${c.keyed ? "Hashes are keyed (HMAC), so they can't be recomputed without the key." : "Hashes are unkeyed. Set HEIMDALL_AUDIT_KEY so nobody can recompute the chain after editing it."}</p>
    <p class="meta">Latest hash, save it somewhere safe to detect truncation:</p>
    <p class="head">${esc(c.head)}</p>
    ${c.problems.length ? `<ul>${c.problems.map((p) => `<li>${p.seq ? "Entry " + p.seq + ": " : ""}${esc(p.problem)}</li>`).join("")}</ul>` : ""}`;
}

function renderApprovals(list) {
  const box = $("approvals");
  box.hidden = !list.length;
  const focused = document.activeElement?.closest?.(".approval")?.dataset.id;
  if (focused) return; // don't redraw while someone is typing a note
  $("approval-list").innerHTML = list.map((a) => {
    const why = (a.policy?.reasons || []).join("; ");
    return `<div class="approval" data-id="${esc(a.action_id)}">
      <div>
        <h3>${esc(a.agent)} wants to call ${esc(a.tool)}</h3>
        <p class="purpose">“${esc(a.request?.purpose || "no purpose given")}”</p>
        <p class="why">${esc(why)}</p>
        <pre style="margin-top:8px">${esc(JSON.stringify(a.request?.arguments ?? {}, null, 2))}</pre>
      </div>
      <div class="actions">
        <input type="text" placeholder="Note (optional)" aria-label="Note for ${esc(a.tool)}">
        <button class="btn yes" data-approve="1">Approve</button>
        <button class="btn no" data-approve="0">Deny</button>
      </div>
    </div>`;
  }).join("");
}

function renderReports(list) {
  if (!list.length) {
    $("reports").innerHTML = `<p class="empty">No claims checked yet.</p>`;
    return;
  }
  const label = { deceptive: "Deceptive", incomplete: "Incomplete", consistent: "Consistent" };
  $("reports").innerHTML = list.slice(0, 8).map((r) => `
    <article class="report">
      <header><span class="verdict ${r.verdict}">${label[r.verdict] || r.verdict}</span><span class="meta">${esc(r.agent)}, ${time(r.ts)}</span></header>
      ${r.claim ? `<blockquote>${esc(r.claim)}</blockquote>` : ""}
      ${r.findings.length ? `<ul>${r.findings.map((f) => `<li class="${f.severity}">${esc(f.message)}</li>`).join("")}</ul>` : `<p class="meta">Matches the ${r.observed.length} observed action(s).</p>`}
    </article>`).join("");
}

const ago = (ts) => {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  return s < 60 ? `${s}s ago` : `${Math.round(s / 60)} min ago`;
};
const describeArgs = (args) => {
  if (!args) return "";
  const v = args.name || args.text || args.keys || (args.x !== undefined ? `(${args.x}, ${args.y})` : "") || args.direction || "";
  return String(v).slice(0, 60);
};

function renderScreen(screen) {
  const banner = $("screen-banner");
  const active = screen.active || [];
  banner.hidden = !active.length;
  if (active.length) {
    const s = active[0];
    const st = s.state || {};
    $("screen-title").textContent = `${s.agent} is controlling your screen`;
    const started = st.screen_started ? `since ${time(st.screen_started)}` : "access granted";
    const last = st.screen_last ? `, last action ${ago(st.screen_last)}` : "";
    $("screen-detail").textContent = `${started}, ${st.screen_actions || 0} screen actions${last}. Access ends at ${time(s.screen_granted_until)} unless you revoke it.` + (active.length > 1 ? ` ${active.length - 1} more agent(s) also have screen access.` : "");
    $("screen-actions").innerHTML = `
      <button class="btn" data-revoke="${esc(s.session_id)}">Revoke screen access</button>
      <button class="btn no" data-status="paused" data-session="${esc(s.session_id)}">Pause agent</button>`;
  }
  const tl = screen.timeline || [];
  if (!tl.length) {
    $("screen-timeline").innerHTML = `<p class="empty">No agent has touched the screen.</p>`;
    return;
  }
  const label = { succeeded: ["allow", "done"], blocked: ["block", "blocked"], denied: ["block", "denied"], pending: ["neutral", "waiting"], failed: ["neutral", "error"] };
  $("screen-timeline").innerHTML = `<ul class="timeline">${tl.slice(0, 40).map((e) => {
    if (e.event) {
      const verb = e.event === "screen_control_started" ? "started controlling the screen" : "stopped controlling the screen";
      return `<li><span class="marker">${time(e.ts)}: ${esc(e.agent)} ${verb}${e.detail ? ` (${esc(e.detail)})` : ""}</span></li>`;
    }
    const [cls, txt] = label[e.status] || ["neutral", e.status];
    return `<li><span class="time">${time(e.ts)}</span><span>${esc((e.tool || "").split(".").pop().replace(/_/g, " "))} <span class="meta">${esc(describeArgs(e.arguments))}</span></span><span class="pill ${cls}">${txt}</span></li>`;
  }).join("")}</ul>`;
}

function renderAlerts(list) {
  if (!list.length) {
    $("alerts").innerHTML = `<p class="empty">No alerts yet.</p>`;
  } else {
    $("alerts").innerHTML = `<div class="alert-list">${list.slice(0, 40).map((a) => `
      <div class="alert ${a.severity}"><i></i><div>
        <p>${esc(a.message)}</p>
        <span class="meta">${esc(a.agent)}, ${time(a.ts)}, ${esc((a.guard || "").replace(/_/g, " "))}</span>
      </div></div>`).join("")}</div>`;
  }
  // Desktop notifications for critical alerts and screen-control starts.
  const newest = list[0]?.seq ?? 0;
  if (state.alertSeq !== null && "Notification" in window && Notification.permission === "granted") {
    list.filter((a) => a.seq > state.alertSeq && (a.severity === "critical" || a.guard === "screen_control"))
      .reverse().forEach((a) => new Notification(a.guard === "screen_control" ? "Screen control started" : "Heimdall alert", { body: `${a.agent}: ${a.message}` }));
  }
  state.alertSeq = Math.max(state.alertSeq ?? 0, newest);
}

function renderSessionsPanel(sessions) {
  const list = sessions.filter((s) => s.controllable);
  if (!list.length) {
    $("sessions").innerHTML = `<p class="empty">No sessions yet.</p>`;
    return;
  }
  $("sessions").innerHTML = list.slice(0, 12).map((s) => {
    const st = s.state || {};
    const badges = [
      s.screen_active ? `<span class="badge screen">controlling screen</span>` : "",
      st.tainted ? `<span class="badge taint" title="${esc((st.taint_reasons || []).join("; "))}">tainted</span>` : "",
      st.decoy_touched ? `<span class="badge taint">touched decoy</span>` : "",
      st.blocked_count ? `<span class="badge">${st.blocked_count} blocked</span>` : "",
    ].join("");
    const controls = s.status === "active"
      ? `<button class="mini" data-status="paused" data-session="${esc(s.session_id)}">Pause</button>
         <button class="mini danger" data-status="quarantined" data-session="${esc(s.session_id)}">Quarantine</button>`
      : `<button class="mini" data-status="active" data-session="${esc(s.session_id)}">Resume</button>`;
    return `<div class="session">
      <header><span class="name">${esc(s.agent)}</span><span class="pill ${s.status}">${esc(s.status)}</span></header>
      <span class="meta">${esc(s.session_id)}${s.status_reason ? `: ${esc(s.status_reason)}` : ""}</span>
      <div>${badges}</div>
      <div class="controls">${controls}</div>
    </div>`;
  }).join("");
}

function renderTools(tools) {
  const review = tools.filter((t) => t.status !== "trusted");
  $("tools-panel").hidden = !review.length;
  $("tools").innerHTML = review.map((t) => `
    <div class="tool-item">
      <span class="tool">${esc(t.tool)}</span> <span class="pill ${t.status === "poisoned" ? "block" : "restrict"}">${t.status === "poisoned" ? "Hidden: looks poisoned" : "Changed since approved"}</span>
      <ul>${(t.reasons || []).slice(0, 3).map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
      <button class="mini" data-trust="${esc(t.tool)}">${t.status === "poisoned" ? "Trust anyway" : "Trust this version"}</button>
    </div>`).join("");
}

async function refreshSessions() {
  const sessions = await api("/api/sessions");
  const sel = $("session");
  const ids = [...new Set(sessions.map((s) => s.session_id))];
  const current = sel.value;
  sel.innerHTML = `<option value="">All sessions</option>` + ids.map((id) => {
    const s = sessions.find((x) => x.session_id === id);
    return `<option value="${esc(id)}">${esc(id)} (${s.events} events)</option>`;
  }).join("");
  sel.value = ids.includes(current) ? current : "";
  $("claim-hint").textContent = state.session ? `Checks against session ${state.session}.` : "Pick a session above first: claims are checked against one session.";
}

async function refresh() {
  try {
    const [overview, actions, approvals, reports, alerts, screen, tools, sessions] = await Promise.all([
      api("/api/overview" + q()), api("/api/actions" + q()), api("/api/approvals"), api("/api/reports" + q()),
      api("/api/alerts" + q()), api("/api/screen"), api("/api/tools"), api("/api/sessions"),
    ]);
    renderAlerts(alerts);
    renderScreen(screen);
    renderTools(tools);
    renderSessionsPanel(sessions);
    state.actions = actions;
    renderStats(overview);
    renderBridge(actions);
    renderFeed(actions);
    renderApprovals(approvals);
    renderReports(reports);
    state.first = false;
  } catch (e) {
    $("chain").textContent = "Dashboard can't reach Heimdall";
    $("chain").className = "chain bad";
    console.error(e);
  }
}

// ---------------------------------------------------------------- events
$("feed").addEventListener("click", (e) => {
  const row = e.target.closest("tr.row");
  if (!row) return;
  const id = row.dataset.id;
  state.open.has(id) ? state.open.delete(id) : state.open.add(id);
  renderFeed(state.actions);
});
$("feed").addEventListener("keydown", (e) => {
  if ((e.key === "Enter" || e.key === " ") && e.target.matches("tr.row")) { e.preventDefault(); e.target.click(); }
});
$("bridge").addEventListener("click", (e) => {
  const seg = e.target.closest(".seg");
  if (!seg) return;
  state.open.add(seg.dataset.id);
  $("only-flagged").checked = false;
  renderFeed(state.actions);
  document.querySelector(`tr.row[data-id="${CSS.escape(seg.dataset.id)}"]`)?.scrollIntoView({ behavior: "smooth", block: "center" });
});
$("approval-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-approve]");
  if (!btn) return;
  const card = btn.closest(".approval");
  const note = card.querySelector("input").value;
  card.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    await api(`/api/approvals/${card.dataset.id}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approve: btn.dataset.approve === "1", reviewer: "dashboard", note }),
    });
  } catch (err) { alert(err.message); }
  document.activeElement?.blur();
  refresh();
});
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-status], [data-revoke], [data-trust]");
  if (!b) return;
  b.disabled = true;
  try {
    if (b.dataset.revoke) await post(`/api/sessions/${encodeURIComponent(b.dataset.revoke)}/revoke-screen`);
    else if (b.dataset.trust) await post(`/api/tools/${encodeURIComponent(b.dataset.trust)}/trust`);
    else await post(`/api/sessions/${encodeURIComponent(b.dataset.session)}/status`, { status: b.dataset.status, reason: `${b.dataset.status === "active" ? "resumed" : b.dataset.status} from the dashboard` });
  } catch (err) { console.error(err); }
  refresh();
});
$("notify").addEventListener("click", async () => {
  if (!("Notification" in window)) { $("notify").textContent = "Notifications not supported here"; return; }
  const p = await Notification.requestPermission();
  $("notify").textContent = p === "granted" ? "Desktop notifications on" : "Notifications blocked in browser";
  $("notify").disabled = p === "granted";
});
if ("Notification" in window && Notification.permission === "granted") {
  $("notify").textContent = "Desktop notifications on";
  $("notify").disabled = true;
}
$("only-flagged").addEventListener("change", () => renderFeed(state.actions));
$("session").addEventListener("change", (e) => {
  state.session = e.target.value; state.open.clear(); state.first = true; state.seen.clear();
  refreshSessions(); refresh();
});
$("chain").addEventListener("click", refresh);
$("claim-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.session) { $("claim-hint").textContent = "Pick a session above first: claims are checked against one session."; return; }
  const agent = state.actions.find((a) => a.session_id === state.session)?.agent || "unknown";
  await api("/api/claims", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: state.session, claim: $("claim-text").value, agent }),
  });
  $("claim-text").value = "";
  refresh();
});

refreshSessions();
refresh();
setInterval(refresh, 2000);
setInterval(refreshSessions, 6000);
