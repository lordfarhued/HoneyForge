(() => {
  const API_LIMIT = 500;
  const HOUR = 60 * 60 * 1000;
  const DAY = 24 * HOUR;
  const MOSCOW_OFFSET = 3 * HOUR;
  const SVG_NS = "http://www.w3.org/2000/svg";
  const PERIODS = {
    1: { label: "24 часа", buckets: 24, step: HOUR },
    7: { label: "7 дней", buckets: 7, step: DAY },
    30: { label: "30 дней", buckets: 30, step: DAY },
  };
  const { parseTimestamp, formatMoscowTime } = window.centerTime;
  const theme = getComputedStyle(document.documentElement);
  const themeColor = (name) => theme.getPropertyValue(name).trim();
  const protocolColors = {
    HTTP: themeColor("--stat-protocol-http"),
    SSH: themeColor("--stat-protocol-ssh"),
    TCP: themeColor("--stat-protocol-tcp"),
    UDP: themeColor("--stat-protocol-udp"),
    OTHER: themeColor("--stat-protocol-unknown"),
    UNKNOWN: themeColor("--stat-protocol-unknown"),
  };
  function shiftedParts(timestamp) {
    const shifted = new Date(timestamp + MOSCOW_OFFSET);
    return {
      year: shifted.getUTCFullYear(),
      month: shifted.getUTCMonth(),
      day: shifted.getUTCDate(),
      hour: shifted.getUTCHours(),
    };
  }

  function periodStart(days, now) {
    const parts = shiftedParts(now);
    if (days === 1) {
      const currentHour = Date.UTC(parts.year, parts.month, parts.day, parts.hour) - MOSCOW_OFFSET;
      return currentHour - (PERIODS[days].buckets - 1) * HOUR;
    }
    const currentDay = Date.UTC(parts.year, parts.month, parts.day) - MOSCOW_OFFSET;
    return currentDay - (PERIODS[days].buckets - 1) * DAY;
  }

  function bucketLabel(timestamp, days) {
    const shifted = new Date(timestamp + MOSCOW_OFFSET);
    if (days === 1) return `${String(shifted.getUTCHours()).padStart(2, "0")}:00`;
    return `${String(shifted.getUTCDate()).padStart(2, "0")}.${String(shifted.getUTCMonth() + 1).padStart(2, "0")}`;
  }

  function buildBuckets(days, now = Date.now()) {
    const definition = PERIODS[days];
    const start = periodStart(days, now);
    return Array.from({ length: definition.buckets }, (_, index) => ({
      start: start + index * definition.step,
      end: start + (index + 1) * definition.step,
      label: bucketLabel(start + index * definition.step, days),
      events: [],
    }));
  }

  function groupEvents(events, days, now = Date.now()) {
    const buckets = buildBuckets(days, now);
    const start = buckets[0].start;
    events.forEach((event) => {
      const timestamp = parseTimestamp(event.occurred_at)?.getTime();
      if (!Number.isFinite(timestamp) || timestamp < start || timestamp > now) return;
      const index = Math.min(buckets.length - 1, Math.floor((timestamp - start) / PERIODS[days].step));
      buckets[index].events.push(event);
    });
    return buckets;
  }

  function protocolFor(event) {
    const declared = typeof event.data?.protocol === "string" ? event.data.protocol.toLowerCase() : "";
    const type = String(event.event_type || "").toLowerCase();
    const combined = `${declared}.${type}`;
    if (combined.includes("ssh")) return "SSH";
    if (combined.includes("http")) return "HTTP";
    if (combined.includes("udp")) return "UDP";
    if (combined.includes("tcp") || combined.includes("connection")) return "TCP";
    return "Не определён";
  }

  function emptyState(container, text) {
    container.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "analytics-empty";
    empty.textContent = text;
    container.append(empty);
  }

  function svgElement(name, attributes = {}) {
    const element = document.createElementNS(SVG_NS, name);
    Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
    return element;
  }

  function appendTitle(element, value) {
    const title = svgElement("title");
    title.textContent = value;
    element.append(title);
  }

  const activityChart = document.getElementById("activity-chart");
  const sourceChart = document.getElementById("source-chart");
  const protocolContent = document.getElementById("protocol-content");
  const topSources = document.getElementById("top-sources");
  const analyticsNotice = document.getElementById("analytics-notice");
  const eventCount = document.getElementById("period-event-count");
  const eventCountLabel = document.getElementById("period-event-label");
  const uniqueSourceCount = document.getElementById("unique-source-count");
  const periodSwitch = document.getElementById("period-switch");
  let selectedDays = 7;
  let analyticsEvents = [];
  let analyticsLimited = false;
  let analyticsRequest = null;

  function renderAxis(container, buckets, days) {
    const axis = document.createElement("div");
    axis.className = "chart-axis";
    axis.style.gridTemplateColumns = `repeat(${buckets.length}, minmax(0, 1fr))`;
    buckets.forEach((bucket, index) => {
      const label = document.createElement("span");
      const show = days === 7 || index === 0 || index === buckets.length - 1 || (days === 1 ? index % 4 === 0 : index % 5 === 0);
      label.textContent = show ? bucket.label : "";
      axis.append(label);
    });
    container.append(axis);
  }

  function renderActivity(buckets, days) {
    if (!activityChart) return;
    if (!buckets.some((bucket) => bucket.events.length)) {
      emptyState(activityChart, "Подозрительно тихо — событий за выбранный период нет.");
      return;
    }
    activityChart.replaceChildren();
    const width = Math.max(360, Math.round(activityChart.clientWidth - 32));
    const height = 160;
    const gap = days === 30 ? 3 : 6;
    const maximum = Math.max(...buckets.map((bucket) => bucket.events.length), 1);
    const slot = width / buckets.length;
    const plotBottom = height - 18;
    const svg = svgElement("svg", { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: "xMidYMid meet", class: "technical-chart", "aria-hidden": "true" });
    [12, 55, 98, plotBottom].forEach((y) => svg.append(svgElement("line", { x1: 0, y1: y, x2: width, y2: y, class: "chart-grid-line" })));
    buckets.forEach((bucket, index) => {
      const value = bucket.events.length;
      const barHeight = value ? Math.max(4, (value / maximum) * (plotBottom - 20)) : 1;
      const rect = svgElement("rect", {
        x: index * slot + gap / 2,
        y: plotBottom - barHeight,
        width: Math.max(2, slot - gap),
        height: barHeight,
        rx: 1,
        class: value ? "chart-bar" : "chart-bar-empty",
      });
      appendTitle(rect, `${bucket.label} МСК — ${value} событий`);
      svg.append(rect);
    });
    activityChart.append(svg);
    renderAxis(activityChart, buckets, days);
  }

  function renderSourceTrend(buckets, days) {
    if (!sourceChart) return;
    const values = buckets.map((bucket) => new Set(bucket.events.map((event) => event.source_ip).filter(Boolean)).size);
    if (!values.some(Boolean)) {
      emptyState(sourceChart, "IP-источники за выбранный период отсутствуют.");
      return;
    }
    sourceChart.replaceChildren();
    const width = Math.max(360, Math.round(sourceChart.clientWidth - 32));
    const height = 128;
    const maximum = Math.max(...values, 1);
    const step = buckets.length === 1 ? width : width / (buckets.length - 1);
    const plotBottom = height - 16;
    const points = values.map((value, index) => ({ x: index * step, y: plotBottom - (value / maximum) * (plotBottom - 18), value }));
    const svg = svgElement("svg", { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: "xMidYMid meet", class: "technical-chart", "aria-hidden": "true" });
    [12, 62, plotBottom].forEach((y) => svg.append(svgElement("line", { x1: 0, y1: y, x2: width, y2: y, class: "chart-grid-line" })));
    const pointList = points.map((point) => `${point.x},${point.y}`).join(" ");
    svg.append(svgElement("polygon", { points: `0,${plotBottom} ${pointList} ${width},${plotBottom}`, class: "chart-area" }));
    svg.append(svgElement("polyline", { points: pointList, class: "chart-line" }));
    points.forEach((point, index) => {
      const circle = svgElement("circle", { cx: point.x, cy: point.y, r: 2.5, class: "chart-point" });
      appendTitle(circle, `${buckets[index].label} МСК — ${point.value} источников`);
      svg.append(circle);
    });
    sourceChart.append(svg);
    renderAxis(sourceChart, buckets, days);
  }

  function renderProtocols(events) {
    if (!protocolContent) return;
    const counts = new Map();
    events.forEach((event) => {
      const protocol = protocolFor(event);
      counts.set(protocol, (counts.get(protocol) || 0) + 1);
    });
    if (!counts.size) {
      emptyState(protocolContent, "Протоколы не определены: событий за период нет.");
      return;
    }
    protocolContent.replaceChildren();
    const total = events.length;
    const svg = svgElement("svg", { viewBox: "0 0 120 120", class: "protocol-donut", role: "img", "aria-label": "Распределение событий по протоколам" });
    const radius = 44;
    const circumference = 2 * Math.PI * radius;
    svg.append(svgElement("circle", { cx: 60, cy: 60, r: radius, class: "protocol-track", transform: "rotate(-90 60 60)" }));
    const legend = document.createElement("div");
    legend.className = "protocol-legend";
    let offset = 0;
    Array.from(counts.entries()).sort((left, right) => right[1] - left[1]).forEach(([protocol, count]) => {
      const color = protocolColors[protocol] || (protocol === "Не определён" ? protocolColors.UNKNOWN : protocolColors.OTHER);
      const length = (count / total) * circumference;
      const segment = svgElement("circle", {
        cx: 60,
        cy: 60,
        r: radius,
        class: "protocol-segment",
        stroke: color,
        transform: "rotate(-90 60 60)",
        "stroke-dasharray": `${length} ${circumference - length}`,
        "stroke-dashoffset": -offset,
      });
      appendTitle(segment, `${protocol}: ${count} (${Math.round((count / total) * 100)}%)`);
      svg.append(segment);
      offset += length;

      const row = document.createElement("div");
      row.className = "protocol-row";
      const swatch = document.createElement("i");
      swatch.className = "protocol-swatch";
      swatch.style.setProperty("--protocol-color", color);
      const name = document.createElement("span");
      name.textContent = protocol;
      const amount = document.createElement("strong");
      amount.textContent = String(count);
      const percentage = document.createElement("small");
      percentage.textContent = `${Math.round((count / total) * 100)}%`;
      row.append(swatch, name, amount, percentage);
      legend.append(row);
    });
    const totalValue = svgElement("text", { x: 60, y: 58, class: "protocol-total" });
    totalValue.textContent = String(total);
    const totalLabel = svgElement("text", { x: 60, y: 72, class: "protocol-total-label" });
    totalLabel.textContent = "СОБЫТИЙ";
    svg.append(totalValue, totalLabel);
    protocolContent.append(svg, legend);
  }

  function renderTopSources(events) {
    if (!topSources) return;
    const counts = new Map();
    events.forEach((event) => {
      if (event.source_ip) counts.set(event.source_ip, (counts.get(event.source_ip) || 0) + 1);
    });
    const ranked = Array.from(counts.entries()).sort((left, right) => right[1] - left[1]).slice(0, 5);
    if (!ranked.length) {
      emptyState(topSources, "Источники за выбранный период отсутствуют.");
      return;
    }
    topSources.replaceChildren();
    const maximum = ranked[0][1];
    ranked.forEach(([source, count]) => {
      const row = document.createElement("div");
      row.className = "source-rank";
      const heading = document.createElement("div");
      heading.className = "source-rank-head";
      const address = document.createElement("span");
      address.textContent = source;
      const amount = document.createElement("strong");
      amount.textContent = String(count);
      heading.append(address, amount);
      const track = document.createElement("div");
      track.className = "source-rank-bar";
      const bar = document.createElement("i");
      bar.style.width = `${(count / maximum) * 100}%`;
      track.append(bar);
      row.append(heading, track);
      topSources.append(row);
    });
  }

  function renderAnalytics() {
    const now = Date.now();
    const buckets = groupEvents(analyticsEvents, selectedDays, now);
    const periodEvents = buckets.flatMap((bucket) => bucket.events);
    const uniqueSources = new Set(periodEvents.map((event) => event.source_ip).filter(Boolean));
    if (eventCount) eventCount.textContent = analyticsLimited ? `${periodEvents.length}+` : String(periodEvents.length);
    if (eventCountLabel) eventCountLabel.textContent = `за ${PERIODS[selectedDays].label}`;
    if (uniqueSourceCount) uniqueSourceCount.textContent = analyticsLimited ? `${uniqueSources.size}+` : String(uniqueSources.size);
    renderActivity(buckets, selectedDays);
    renderSourceTrend(buckets, selectedDays);
    renderProtocols(periodEvents);
    renderTopSources(periodEvents);
  }

  async function loadAnalytics(days) {
    selectedDays = days;
    periodSwitch?.querySelectorAll("button").forEach((button) => {
      button.setAttribute("aria-pressed", String(Number(button.dataset.period) === days));
      button.disabled = true;
    });
    analyticsNotice.dataset.state = "loading";
    analyticsNotice.textContent = "Загрузка аналитики…";
    analyticsRequest?.abort();
    analyticsRequest = new AbortController();
    const request = analyticsRequest;
    const now = Date.now();
    const start = periodStart(days, now);
    const query = new URLSearchParams({
      from_time: new Date(start).toISOString(),
      to_time: new Date(now).toISOString(),
      limit: String(API_LIMIT),
    });
    try {
      const response = await fetch(`/api/v1/events?${query}`, { signal: request.signal, headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      if (!Array.isArray(payload)) throw new Error("Некорректный формат ответа");
      const merged = new Map(payload.map((event) => [event.external_id, event]));
      analyticsEvents.forEach((event) => {
        const timestamp = parseTimestamp(event.occurred_at)?.getTime();
        if (Number.isFinite(timestamp) && timestamp >= start && timestamp <= Date.now()) merged.set(event.external_id, event);
      });
      analyticsEvents = Array.from(merged.values())
        .sort((left, right) => (parseTimestamp(right.occurred_at)?.getTime() || 0) - (parseTimestamp(left.occurred_at)?.getTime() || 0))
        .slice(0, API_LIMIT);
      analyticsLimited = payload.length === API_LIMIT;
      analyticsNotice.dataset.state = analyticsLimited ? "limited" : "ready";
      analyticsNotice.textContent = analyticsLimited
        ? "API вернул последние 500 событий периода. Значения с «+» и графики могут быть неполными."
        : `Учтено событий: ${payload.length}. Данные получены из PostgreSQL через существующий API.`;
      renderAnalytics();
    } catch (error) {
      if (error.name === "AbortError") return;
      analyticsNotice.dataset.state = "error";
      analyticsNotice.textContent = "Аналитика временно недоступна. Оперативный поток событий продолжает работать отдельно.";
      [activityChart, sourceChart, protocolContent, topSources].filter(Boolean).forEach((container) => emptyState(container, "Не удалось загрузить данные."));
    } finally {
      if (analyticsRequest === request) {
        periodSwitch?.querySelectorAll("button").forEach((button) => { button.disabled = false; });
      }
    }
  }

  periodSwitch?.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-period]");
    if (!button || button.disabled) return;
    loadAnalytics(Number(button.dataset.period));
  });

  async function loadHosts() {
    const container = document.getElementById("host-summary");
    if (!container) return;
    try {
      const response = await fetch("/api/v1/hosts", { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const hosts = await response.json();
      if (!Array.isArray(hosts)) throw new Error("Некорректный формат ответа");
      if (!hosts.length) {
        emptyState(container, "Никто не выходит на связь.");
        return;
      }
      container.replaceChildren();
      hosts.slice(0, 5).forEach((host) => {
        const row = document.createElement("div");
        row.className = "host-summary-row";
        const identity = document.createElement("div");
        const name = document.createElement("strong");
        name.textContent = host.name;
        const address = document.createElement("small");
        address.textContent = `${host.management_address} · ${formatMoscowTime(host.last_seen_at)}`;
        identity.append(name, address);
        const status = document.createElement("span");
        const statusNames = { online: "Онлайн", offline: "Офлайн", degraded: "Нестабильно" };
        status.className = `status-pill status-${host.status || "neutral"}`;
        status.textContent = statusNames[host.status] || "Неизвестно";
        row.append(identity, status);
        container.append(row);
      });
      if (hosts.length > 5) {
        const more = document.createElement("div");
        more.className = "host-summary-more";
        more.textContent = `Ещё хостов: ${hosts.length - 5}`;
        container.append(more);
      }
    } catch {
      emptyState(container, "Не удалось получить состояние хостов.");
    }
  }

  if (activityChart) {
    loadAnalytics(selectedDays);
    loadHosts();
    const hostStatusTimer = window.setInterval(() => {
      if (!document.hidden) loadHosts();
    }, 15000);
    window.addEventListener("beforeunload", () => window.clearInterval(hostStatusTimer), { once: true });
    if ("ResizeObserver" in window) {
      let observedWidth = Math.round(activityChart.clientWidth);
      let resizeTimer = null;
      const chartObserver = new ResizeObserver(() => {
        const nextWidth = Math.round(activityChart.clientWidth);
        if (Math.abs(nextWidth - observedWidth) < 16) return;
        observedWidth = nextWidth;
        window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(renderAnalytics, 100);
      });
      chartObserver.observe(activityChart);
      window.addEventListener("beforeunload", () => chartObserver.disconnect(), { once: true });
    }
  }

  const feed = document.getElementById("event-feed");
  if (!feed) return;
  const streamStatus = document.getElementById("stream-status");
  const setStreamState = (state, label) => {
    if (!streamStatus) return;
    streamStatus.hidden = false;
    streamStatus.dataset.state = state;
    streamStatus.querySelector("strong").textContent = label;
  };

  const newest = feed.querySelector("[data-created-at]");
  const seen = new Set(Array.from(feed.querySelectorAll("[data-event-id]"), (row) => row.dataset.eventId));
  if (!sessionStorage.getItem("honeyforgeEventCursor") && newest) {
    sessionStorage.setItem("honeyforgeEventCursor", newest.dataset.createdAt);
  }
  let retryDelay = 500;
  let stopped = false;
  let socket = null;

  const render = (event) => {
    if (seen.has(event.external_id)) return;
    seen.add(event.external_id);
    document.getElementById("event-empty")?.remove();
    const row = document.createElement("div");
    row.className = "event-row";
    row.dataset.eventId = event.external_id;
    row.dataset.createdAt = event.created_at;
    const type = document.createElement("span");
    const eventProtocol = protocolFor(event);
    const eventProtocolClass = { HTTP: "http", SSH: "ssh", TCP: "tcp", UDP: "udp" }[eventProtocol] || "unknown";
    type.className = `event-type event-type-${eventProtocolClass}`;
    type.textContent = event.event_type;
    const source = document.createElement("span");
    source.className = "mono";
    source.textContent = event.source_ip || "источник не указан";
    const marker = document.createElement("span");
    if (event.is_test) {
      marker.className = "level level-medium";
      marker.textContent = "ТЕСТ";
    }
    const time = document.createElement("small");
    time.textContent = formatMoscowTime(event.occurred_at);
    row.append(type, source, marker, time);
    feed.prepend(row);
    while (feed.querySelectorAll(".event-row").length > 8) feed.lastElementChild.remove();
    sessionStorage.setItem("honeyforgeEventCursor", event.created_at);

    const timestamp = parseTimestamp(event.occurred_at)?.getTime();
    if (Number.isFinite(timestamp) && timestamp >= periodStart(selectedDays, Date.now())) {
      const known = analyticsEvents.some((item) => item.external_id === event.external_id);
      if (!known) {
        analyticsEvents = [event, ...analyticsEvents].slice(0, API_LIMIT);
        renderAnalytics();
      }
    }
  };

  const connect = () => {
    setStreamState("connecting", "Подключение к потоку");
    const since = sessionStorage.getItem("honeyforgeEventCursor") || "";
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const url = `${scheme}://${location.host}/ws/events${since ? `?since=${encodeURIComponent(since)}` : ""}`;
    socket = new WebSocket(url);
    socket.addEventListener("open", () => {
      retryDelay = 500;
      setStreamState("online", "Поток подключён");
    });
    socket.addEventListener("message", (message) => {
      try { render(JSON.parse(message.data)); } catch { /* malformed frames are ignored */ }
    });
    socket.addEventListener("close", () => {
      setStreamState("offline", "Поток недоступен");
      if (stopped) return;
      window.setTimeout(connect, retryDelay);
      retryDelay = Math.min(retryDelay * 2, 10000);
    });
  };

  window.addEventListener("beforeunload", () => {
    stopped = true;
    analyticsRequest?.abort();
    socket?.close();
  });
  connect();
})();
