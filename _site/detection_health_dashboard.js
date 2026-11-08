(() => {
  const dataElement = document.getElementById("dashboard-data");
  const model = JSON.parse(dataElement.textContent);
  const state = { query: "", health: "", severity: "", technique: "", sort: "name", direction: 1 };
  const byId = (id) => document.getElementById(id);
  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };
  const element = (tag, className = "") => { const node = document.createElement(tag); if (className) node.className = className; return node; };
  const text = (node, value) => { node.textContent = value === null || value === undefined || value === "" ? "N/A" : String(value); return node; };
  const statusClass = (value) => String(value || "UNKNOWN").replaceAll(" ", "_");
  const ageText = (timestamp) => { const age = Math.max(0, Date.now() - Date.parse(timestamp)); const minutes = Math.floor(age / 60000); if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`; const hours = Math.floor(minutes / 60); if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"}`; const days = Math.floor(hours / 24); return `${days} day${days === 1 ? "" : "s"}`; };
  const badge = (value) => { const node = element("span", `badge ${statusClass(value)}`); return text(node, value); };
  const field = (label, value, target) => { const dt = element("dt"); text(dt, label); const dd = element("dd"); if (value instanceof Node) dd.appendChild(value); else text(dd, value); target.append(dt, dd); };
  const addOptions = (id, values) => { const select = byId(id); const any = element("option"); any.value = ""; any.textContent = "All"; select.appendChild(any); values.forEach((value) => { const option = element("option"); option.value = value; option.textContent = value; select.appendChild(option); }); };
  const formatAlert = (row) => !row.alert_activity.available ? "N/A" : row.alert_activity.count === 0 ? "0" : String(row.alert_activity.count);
  const renderSummary = () => {
    const cards = [
      ["Repository-managed", model.summary.repository_managed], ["Deployed Elastic rules", model.summary.deployed_rules], ["Enabled / disabled", `${model.summary.enabled} / ${model.summary.disabled}`], ["Healthy", model.summary.statuses.HEALTHY], ["Execution concerns", model.summary.statuses.FAILED + model.summary.statuses.DEGRADED + model.summary.statuses.STALE], ["Requires review", model.summary.review_count], ["Alerts in lookback", model.summary.alert_available ? model.summary.total_alerts : "N/A"]
    ];
    const parent = byId("summary-cards"); clear(parent); cards.forEach(([label, value]) => { const card = element("article", "card"); const title = element("div", "card-label"); text(title, label); const amount = element("div", "card-value"); text(amount, value); card.append(title, amount); parent.appendChild(card); });
  };
  const filteredRows = () => model.rows.filter((row) => {
    const haystack = [row.name, row.rule_id, row.uuid, ...(row.techniques || [])].join(" ").toLowerCase();
    return (!state.query || haystack.includes(state.query)) && (!state.health || row.operational_health.status === state.health) && (!state.severity || row.severity === state.severity) && (!state.technique || row.techniques.includes(state.technique));
  }).sort((left, right) => {
    const value = (row) => ({ name: row.name, rule_id: row.rule_id, severity: row.severity, type: row.type, status: row.operational_health.status, alert_count: row.alert_activity.count ?? -1 })[state.sort] ?? "";
    return String(value(left)).localeCompare(String(value(right)), undefined, { numeric: true }) * state.direction;
  });
  const renderRows = () => {
    const rows = filteredRows(); const body = byId("inventory-body"); clear(body); text(byId("inventory-count"), `${rows.length} of ${model.rows.length} detections`);
    rows.forEach((row) => { const tr = element("tr"); tr.dataset.rule = row.uuid || row.rule_id; const values = [
      [row.name, row.uuid || "No deployed UUID"], [row.rule_id], [row.techniques.length ? row.techniques.join(", ") : "N/A"], [row.severity], [row.type], [row.deployment.state + (row.deployment.enabled === null ? "" : row.deployment.enabled ? " · enabled" : " · disabled")], [row.operational_health.status], [row.operational_health.last_execution.date || "N/A"], [formatAlert(row)], [row.review_flags.length ? row.review_flags.join(", ") : "None"]
    ];
      values.forEach((parts, index) => { const td = element("td"); if (index === 0) { const name = element("div", "rule-name"); text(name, parts[0]); const sub = element("div", "small"); text(sub, parts[1]); td.append(name, sub); } else if (index === 5 || index === 6) { td.appendChild(badge(parts[0])); } else if (index === 9 && row.review_flags.length) { row.review_flags.forEach((flag) => { const marker = badge(flag); marker.classList.add("flag"); td.appendChild(marker); }); } else { text(td, parts[0]); } tr.appendChild(td); });
      tr.addEventListener("click", () => renderDetail(row)); body.appendChild(tr);
    });
  };
  const renderDetail = (row) => { const target = byId("rule-detail"); clear(target); target.className = ""; const title = element("h2"); text(title, row.name); const grid = element("dl", "detail-grid"); field("Stable rule ID", row.rule_id, grid); field("Elastic UUID", row.uuid, grid); field("Deployment", row.deployment.state, grid); field("Enabled", row.deployment.enabled === null ? "N/A" : row.deployment.enabled ? "Enabled" : "Disabled", grid); field("Operational health", row.operational_health.status, grid); field("Last execution", row.operational_health.last_execution.date, grid); field("Alert activity", formatAlert(row), grid); field("Last alert", row.alert_activity.last_alert, grid); field("MITRE ATT&CK", row.techniques.join(", ") || "N/A", grid); field("Validation", `${row.validation_health.manifest_coverage}; fixture results: ${row.validation_health.offline_fixture_tests}`, grid); field("Effectiveness", `${row.detection_effectiveness.status}: ${row.detection_effectiveness.note}`, grid); field("Review flags", row.review_flags.join(", ") || "None", grid); target.append(title, grid); };
  const reviewList = (title, items, formatter) => { const wrap = element("section", "review-group"); const heading = element("h3"); text(heading, title); const list = element("ul"); if (!items.length) { const item = element("li"); text(item, "None"); list.appendChild(item); } else { items.forEach((item) => { const line = element("li"); text(line, formatter(item)); list.appendChild(line); }); } wrap.append(heading, list); return wrap; };
  const renderReviews = () => { const target = byId("review-sections"); clear(target); target.append(
    reviewList("Zero alerts in lookback", model.review_sections.zero_alerts, (row) => `${row.name} (${row.rule_id})`),
    reviewList("Failed, degraded, or stale", model.review_sections.execution_concerns, (row) => `${row.name}: ${row.operational_health.status}`),
    reviewList("Potential duplicate names", model.review_sections.duplicate_candidates, (group) => group.map((row) => `${row.name} [${row.uuid}]`).join("; ")),
    reviewList("Insufficient health data", model.review_sections.insufficient_data, (row) => `${row.name}: ${row.operational_health.status}`)
  ); };
  const renderLimitations = () => { const list = byId("limitations"); clear(list); model.limitations.forEach((item) => { const li = element("li"); text(li, item); list.appendChild(li); }); };
  const bind = () => { byId("search").addEventListener("input", (event) => { state.query = event.target.value.toLowerCase().trim(); renderRows(); }); [["health-filter", "health"], ["severity-filter", "severity"], ["technique-filter", "technique"]].forEach(([id, key]) => byId(id).addEventListener("change", (event) => { state[key] = event.target.value; renderRows(); })); document.querySelectorAll("th[data-sort]").forEach((header) => header.addEventListener("click", () => { const next = header.dataset.sort; state.direction = state.sort === next ? -state.direction : 1; state.sort = next; renderRows(); })); };
  const status = byId("snapshot-status"); text(status, `${model.snapshot.is_live ? "Live" : "Historical"} snapshot generated ${model.snapshot.generated_at} · age ${ageText(model.snapshot.generated_at)} · ${model.snapshot.note || "No live browser connection."}`);
  addOptions("health-filter", model.filters.statuses); addOptions("severity-filter", model.filters.severities); addOptions("technique-filter", model.filters.techniques); renderSummary(); renderRows(); renderReviews(); renderLimitations(); bind();
})();
