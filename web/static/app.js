const STATUS = {
  online: "онлайн",
  slow: "медленно",
  offline: "нет порта",
  timeout: "нет ответа",
  auth: "авторизация",
  error: "ошибка",
};
const FILTERS = [
  ["all", "Все"],
  ["up", "Онлайн"],
  ["down", "Проблемы"],
  ["auth", "Авторизация"],
  ["changed", "Смена IP"],
  ["pending", "Ожидает"],
];
const KIND = { private: "серый", cgnat: "CGNAT" };

const state = {
  data: null,
  filter: "all",
  groupKey: null,
  groupActive: false,
  drawerId: null,
  authRequired: false,
  prevIdsUp: null,
};

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, kids = []) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([key, value]) => {
    if (value == null || value === false) return;
    if (key === "class") node.className = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, value);
  });
  kids.flat().forEach((kid) => {
    if (kid == null || kid === false) return;
    node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  });
  return node;
}

function detail(data) {
  if (!data) return "ошибка запроса";
  if (typeof data.detail === "string") return data.detail;
  if (Array.isArray(data.detail)) return data.detail.map((item) => item.msg || "ошибка").join("; ");
  return "ошибка запроса";
}

async function api(path, options = {}) {
  const body = options.body;
  const isForm = typeof FormData !== "undefined" && body instanceof FormData;
  const headers = { ...(options.headers || {}) };
  let payload = body;
  if (body && !isForm && typeof body !== "string") {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const response = await fetch(path, { method: options.method || "GET", headers, body: payload, credentials: "same-origin" });
  const text = await response.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { detail: text }; }
  }
  if (!response.ok) {
    const error = new Error(detail(data));
    error.status = response.status;
    if (response.status === 403) showBlocked(error.message);
    throw error;
  }
  return data;
}

function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => node.classList.add("hidden"), 4000);
}

function ago(iso) {
  if (!iso) return "ещё не проверялся";
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${Math.floor(seconds)} с назад`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} мин назад`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} ч назад`;
  return new Date(iso).toLocaleString();
}

function isUp(proxy) {
  return proxy.last_status === "online" || proxy.last_status === "slow";
}

function matches(proxy) {
  if (state.groupActive && proxy.address !== state.groupKey) return false;
  if (state.filter === "up" && !isUp(proxy)) return false;
  if (state.filter === "down" && !["offline", "timeout", "error"].includes(proxy.last_status)) return false;
  if (state.filter === "auth" && proxy.last_status !== "auth") return false;
  if (state.filter === "changed" && !proxy.exit_ip_changed) return false;
  if (state.filter === "pending" && proxy.last_status) return false;
  const query = $("search").value.trim().toLowerCase();
  if (!query) return true;
  const hay = [proxy.address, proxy.host, proxy.port, proxy.name, proxy.last_exit_ip, proxy.prev_exit_ip]
    .filter(Boolean).join(" ").toLowerCase();
  return hay.includes(query);
}

function renderRound() {
  const round = state.data && state.data.round;
  const label = $("round-label");
  const button = $("check-now");
  if (!round) return;
  button.disabled = false;
  button.textContent = round.running ? "Идёт проверка" : "Проверить сейчас";
  if (round.running) {
    label.textContent = `проверяю ${round.checked || ""}`.trim();
    return;
  }
  const bits = ["прямая проверка с этого сервера"];
  if (round.last_duration_sec != null) bits.push(`круг ${round.last_duration_sec} с`);
  if (round.next_check_at) {
    const left = Math.max(0, Math.round(round.next_check_at - Date.now() / 1000));
    bits.push(`следующий через ${left} с`);
  }
  label.textContent = bits.join(" · ");
}

function renderStats() {
  const stats = state.data.stats;
  const cards = [
    ["Всего", stats.enabled, "", ""],
    ["Онлайн", stats.up, "up", stats.slow ? `${stats.slow} медл.` : ""],
    ["Проблемы", stats.down, stats.down ? "down" : "", ""],
    ["Авторизация", stats.auth, stats.auth ? "warn" : "", ""],
    ["Смена IP", stats.changed, stats.changed ? "warn" : "", ""],
    ["Уникальные IP", stats.unique_ips || 0, "", "за всё время"],
    ["Повторы", stats.repeated_ips || 0, stats.repeated_ips ? "warn" : "", stats.repeat_extra ? `ещё ${stats.repeat_extra} раз` : "адрес вернулся"],
  ];
  $("stats").replaceChildren(...cards.map(([title, value, kind, note]) => h("div", { class: `stat ${kind}` }, [
    h("b", {}, [value]),
    h("span", {}, [note ? `${title} · ${note}` : title]),
  ])));
  const banner = $("banner");
  if (stats.all_failed) {
    banner.textContent = "Все прокси недоступны. Проверьте, что с этой машины открываются их порты, и что URL проверки отвечает.";
    banner.classList.remove("hidden");
  } else banner.classList.add("hidden");
}

function renderGroups() {
  const groups = state.data.groups;
  $("groups").replaceChildren(...groups.map((group) => {
    const active = state.groupActive && state.groupKey === group.address;
    const ratio = group.total ? Math.round((group.up / group.total) * 100) : 0;
    return h("button", {
      type: "button",
      class: `group${active ? " active" : ""}`,
      onclick: () => {
        if (active) state.groupActive = false;
        else {
          state.groupActive = true;
          state.groupKey = group.address;
        }
        render();
      },
    }, [
      h("strong", {}, [group.address || "Без адреса"]),
      h("em", {}, [`${group.up}/${group.total} онлайн`]),
      h("div", { class: "bar" }, [h("i", { style: `width:${ratio}%` })]),
    ]);
  }));
}

function renderFilters() {
  $("filters").replaceChildren(...FILTERS.map(([id, label]) => h("button", {
    type: "button",
    "aria-pressed": state.filter === id ? "true" : "false",
    onclick: () => { state.filter = id; render(); },
  }, [label])));
}

function renderRows() {
  let rows = state.data.proxies.filter(matches);
  if ($("problems-first").checked) {
    const rank = (proxy) => {
      if (!proxy.enabled) return 6;
      if (proxy.last_status === "auth") return 0;
      if (["offline", "timeout", "error"].includes(proxy.last_status)) return 1;
      if (!proxy.last_status) return 2;
      if (proxy.last_status === "slow") return 3;
      if (proxy.exit_ip_changed) return 4;
      return 5;
    };
    rows = [...rows].sort((a, b) => rank(a) - rank(b) || String(a.address).localeCompare(String(b.address)) || a.port - b.port);
  }
  if (!rows.length) {
    const text = state.data.proxies.length ? "Ничего не найдено" : "Список пуст. Загрузите Excel с колонками ip, port, login, password, address.";
    $("rows").replaceChildren(h("tr", {}, [h("td", { colspan: "6", class: "empty" }, [text])]));
    return;
  }
  $("rows").replaceChildren(...rows.map((proxy) => {
    const status = proxy.enabled ? (proxy.last_status || "pending") : "off";
    const label = proxy.enabled ? (STATUS[proxy.last_status] || "ожидает") : "выключен";
    const kind = KIND[proxy.exit_ip_kind] || "";
    return h("tr", { class: proxy.enabled ? "" : "dim", onclick: () => openDrawer(proxy.id) }, [
      h("td", {}, [proxy.address || "—"]),
      h("td", {}, [
        h("span", { class: "mono" }, [`${proxy.host}:${proxy.port}`]),
        proxy.name ? h("span", { class: "name" }, [proxy.name]) : null,
      ]),
      h("td", {}, [
        h("span", { class: `pill st-${status}` }, [h("i", { class: "dot" }), label]),
        proxy.fail_streak > 1 ? h("span", { class: "err" }, [`${proxy.fail_streak} подряд`]) : null,
        proxy.last_error ? h("span", { class: "err" }, [proxy.last_error]) : null,
      ]),
      h("td", { class: "mono" }, [proxy.last_latency_ms == null ? "—" : proxy.last_latency_ms]),
      h("td", { class: "mono" }, [
        proxy.last_exit_ip || "—",
        kind ? h("span", { class: "tag" }, [kind]) : null,
        proxy.exit_ip_changed && proxy.prev_exit_ip ? h("span", { class: "err" }, [`было ${proxy.prev_exit_ip}`]) : null,
      ]),
      h("td", {}, [ago(proxy.last_checked_at)]),
    ]);
  }));
}

function render() {
  if (!state.data) return;
  renderRound();
  renderStats();
  renderGroups();
  renderFilters();
  renderRows();
  if (state.drawerId) fillDrawer(state.data.proxies.find((proxy) => proxy.id === state.drawerId));
}

function noticeChanges(proxies) {
  const up = new Set(proxies.filter((proxy) => proxy.enabled && isUp(proxy)).map((proxy) => proxy.id));
  if (state.prevIdsUp) {
    const fell = [...state.prevIdsUp].filter((id) => !up.has(id));
    if (fell.length === 1) {
      const proxy = proxies.find((item) => item.id === fell[0]);
      toast(proxy ? `${proxy.host}:${proxy.port} недоступен` : "Прокси недоступен");
    } else if (fell.length > 1) toast(`${fell.length} прокси стали недоступны`);
  }
  state.prevIdsUp = up;
}

async function poll() {
  try {
    const data = await api("/api/overview");
    noticeChanges(data.proxies);
    state.data = data;
    render();
  } catch (error) {
    if (error.status === 401) showLogin();
    else if (error.status === 403) showBlocked(error.message);
    else $("round-label").textContent = error.message;
  }
}

function showLogin() {
  $("app-view").classList.add("hidden");
  $("blocked-note").classList.add("hidden");
  $("login-form").classList.remove("hidden");
  $("login-view").classList.remove("hidden");
}

function showBlocked(message) {
  $("app-view").classList.add("hidden");
  $("login-form").classList.add("hidden");
  $("login-view").classList.remove("hidden");
  $("blocked-note").classList.remove("hidden");
  $("blocked-text").textContent = message || "доступ с этого адреса закрыт";
}

function showApp() {
  $("login-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  $("logout").hidden = !state.authRequired;
}

async function openDrawer(id) {
  state.drawerId = id;
  $("drawer").classList.remove("hidden");
  $("drawer").setAttribute("aria-hidden", "false");
  const payload = await api(`/api/proxies/${id}/history`);
  fillDrawer(payload.proxy, payload.checks, payload.ips);
}

function fillDrawer(proxy, checks, ips) {
  if (!proxy) {
    closeDrawer();
    return;
  }
  const card = document.querySelector(".drawer-card");
  const scrollTop = card ? card.scrollTop : 0;
  const body = $("drawer-body");
  const previous = checks ? null : body.querySelector(".history");
  const previousIps = ips ? null : body.querySelector(".ips");
  body.replaceChildren(
    h("p", { class: "eyebrow" }, [proxy.address || "без адреса"]),
    h("h2", { class: "mono" }, [`${proxy.host}:${proxy.port}`]),
    h("p", { class: "sub" }, [proxy.enabled ? (STATUS[proxy.last_status] || "ожидает проверки") : "выключен"]),
    h("div", { class: "kv" }, [
      h("span", {}, ["Имя"]), h("b", {}, [proxy.name || "—"]),
      h("span", {}, ["Протокол"]), h("b", {}, [proxy.protocol]),
      h("span", {}, ["Внешний IP"]), h("b", { class: "mono" }, [proxy.last_exit_ip || "—"]),
      h("span", {}, ["Уникальные"]), h("b", {}, [proxy.unique_ips || 0]),
      h("span", {}, ["Повторы"]), h("b", {}, [proxy.repeated_ips || 0]),
      h("span", {}, ["Предыдущий"]), h("b", { class: "mono" }, [proxy.prev_exit_ip || "—"]),
      h("span", {}, ["Задержка"]), h("b", {}, [proxy.last_latency_ms == null ? "—" : `${proxy.last_latency_ms} мс`]),
      h("span", {}, ["Ошибка"]), h("b", {}, [proxy.last_error || "—"]),
    ]),
    h("div", { class: "drawer-actions" }, [
      h("button", { type: "button", class: "primary", onclick: () => recheck(proxy.id) }, ["Проверить"]),
      h("button", { type: "button", onclick: () => toggle(proxy) }, [proxy.enabled ? "Выключить" : "Включить"]),
      h("button", { type: "button", class: "danger", onclick: () => remove(proxy) }, ["Удалить"]),
    ]),
    h("h3", {}, ["IP за всё время"]),
    previousIps || h("ul", { class: "ips history" }, [h("li", {}, [h("span", {}, ["открываю…"])])]),
    h("h3", {}, ["Последние проверки"]),
    previous || h("ul", { class: "history" }, [h("li", {}, [h("span", {}, ["открываю…"])])]),
  );
  if (checks) renderHistory(checks);
  if (ips) renderIps(ips);
  if (card) card.scrollTop = scrollTop;
}

function renderIps(ips) {
  const list = $("drawer-body").querySelector(".ips");
  if (!list) return;
  if (!ips.length) {
    list.replaceChildren(h("li", {}, [h("span", {}, ["внешних IP ещё не было"])]));
    return;
  }
  list.replaceChildren(...ips.map((item) => h("li", {}, [
    h("span", { class: "mono" }, [item.exit_ip]),
    h("span", { class: "mono" }, [`× ${item.hits}`]),
    h("span", {}, [ago(item.last_seen)]),
  ])));
}

function renderHistory(checks) {
  const list = $("drawer-body").querySelector(".history");
  if (!list) return;
  if (!checks.length) {
    list.replaceChildren(h("li", {}, [h("span", {}, ["проверок ещё не было"])]));
    return;
  }
  list.replaceChildren(...checks.map((check) => h("li", {}, [
    h("span", {}, [STATUS[check.status] || check.status]),
    h("span", { class: "mono" }, [check.exit_ip || check.error || ""]),
    h("span", { class: "mono" }, [check.latency_ms == null ? "" : `${check.latency_ms}`]),
  ])));
}

function closeDrawer() {
  state.drawerId = null;
  $("drawer").classList.add("hidden");
  $("drawer").setAttribute("aria-hidden", "true");
}

async function recheck(id) {
  try {
    await api(`/api/proxies/${id}/check`, { method: "POST" });
    await poll();
    const payload = await api(`/api/proxies/${id}/history`);
    fillDrawer(payload.proxy, payload.checks, payload.ips);
  } catch (error) {
    toast(error.message);
  }
}

async function toggle(proxy) {
  await api(`/api/proxies/${proxy.id}`, { method: "PATCH", body: { enabled: !proxy.enabled } });
  await poll();
}

async function remove(proxy) {
  if (!confirm(`Удалить ${proxy.host}:${proxy.port}?`)) return;
  await api(`/api/proxies/${proxy.id}`, { method: "DELETE" });
  closeDrawer();
  await poll();
}

async function download(path, filename) {
  const response = await fetch(path, { credentials: "same-origin" });
  if (!response.ok) {
    toast("не удалось скачать файл");
    return;
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = h("a", { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function openSettings() {
  const settings = state.data.settings;
  $("set-interval").value = settings.interval_sec;
  $("set-grace").value = settings.restart_grace_sec;
  $("set-timeout").value = settings.timeout_sec;
  $("set-concurrency").value = settings.concurrency;
  $("set-slow").value = settings.slow_ms;
  $("set-url").value = settings.check_url;
  $("settings-error").textContent = "";
  $("settings-dialog").showModal();
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("login-error").textContent = "";
  try {
    await api("/api/login", { method: "POST", body: { password: $("login-password").value } });
    showApp();
    await poll();
  } catch (error) {
    $("login-error").textContent = error.message;
  }
});

$("logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  showLogin();
});

$("check-now").addEventListener("click", async () => {
  await api("/api/check-now", { method: "POST" });
  await poll();
});

$("open-import").addEventListener("click", () => {
  $("import-result").replaceChildren();
  $("import-dialog").showModal();
});
$("import-cancel").addEventListener("click", () => $("import-dialog").close());
$("import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("import-file").files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  form.append("replace_missing", $("replace-missing").checked ? "true" : "false");
  try {
    const result = await api("/api/import", { method: "POST", body: form });
    const lines = [`добавлено ${result.created}, обновлено ${result.updated}`];
    if (result.deleted) lines.push(`удалено ${result.deleted}`);
    if (result.replace_skipped) lines.push("в файле есть ошибки, лишние прокси не удалялись");
    const box = $("import-result");
    box.replaceChildren(h("p", {}, [lines.join(". ")]));
    if (result.errors.length) {
      box.append(h("ul", {}, result.errors.slice(0, 12).map((item) => h("li", {}, [`строка ${item.row}: ${item.message}`]))));
    } else $("import-dialog").close();
    $("import-file").value = "";
    await poll();
  } catch (error) {
    $("import-result").replaceChildren(h("p", {}, [error.message]));
  }
});

$("export-xlsx").addEventListener("click", () => download("/api/export.xlsx", "proxies.xlsx"));
$("open-settings").addEventListener("click", openSettings);
$("settings-cancel").addEventListener("click", () => $("settings-dialog").close());
$("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("settings-error").textContent = "";
  try {
    await api("/api/settings", {
      method: "PUT",
      body: {
        interval_sec: Number($("set-interval").value),
        restart_grace_sec: Number($("set-grace").value),
        timeout_sec: Number($("set-timeout").value),
        concurrency: Number($("set-concurrency").value),
        slow_ms: Number($("set-slow").value),
        check_url: $("set-url").value.trim(),
      },
    });
    $("settings-dialog").close();
    await poll();
  } catch (error) {
    $("settings-error").textContent = error.message;
  }
});
$("wipe").addEventListener("click", async () => {
  if (!confirm("Удалить все прокси и историю проверок?")) return;
  await api("/api/proxies", { method: "DELETE" });
  $("settings-dialog").close();
  closeDrawer();
  await poll();
});
$("drawer-close").addEventListener("click", closeDrawer);
$("drawer").addEventListener("click", (event) => {
  if (event.target === $("drawer")) closeDrawer();
});
$("search").addEventListener("input", renderRows);
$("problems-first").addEventListener("change", renderRows);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDrawer();
});

async function boot() {
  const session = await api("/api/session");
  state.authRequired = session.auth_required;
  if (session.auth_required && !session.authenticated) {
    showLogin();
    return;
  }
  showApp();
  await poll();
  setInterval(() => { if (state.data) renderRound(); }, 1000);
  setInterval(() => { if (!$("app-view").classList.contains("hidden")) poll(); }, 3000);
}

boot().catch((error) => {
  if (error.status === 403) showBlocked(error.message);
  else {
    showLogin();
    $("login-error").textContent = error.message;
  }
});
