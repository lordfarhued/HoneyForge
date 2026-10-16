(() => {
  const moscowFormatter = new Intl.DateTimeFormat("ru-RU", {
    timeZone: "Europe/Moscow",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const parseTimestamp = (value) => {
    const text = String(value || "");
    const normalized = /(?:Z|[+-]\d{2}:\d{2})$/i.test(text) ? text : `${text}Z`;
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? null : date;
  };
  const formatMoscowTime = (value, fallback = "—") => {
    const date = value instanceof Date ? value : parseTimestamp(value);
    if (!date) return fallback;
    const parts = Object.fromEntries(
      moscowFormatter.formatToParts(date).map((part) => [part.type, part.value]),
    );
    return `${parts.day}.${parts.month}.${parts.year} ${parts.hour}:${parts.minute}:${parts.second} МСК`;
  };
  window.centerTime = Object.freeze({ parseTimestamp, formatMoscowTime });

  const isTyping = (target) => target instanceof Element && Boolean(target.closest("input, textarea, select, [contenteditable='true']"));

  const sidebarToggle = document.getElementById("sidebar-toggle");
  const collapsedKey = "nePalimsyaSidebarCollapsed";
  const setSidebarCollapsed = (collapsed) => {
    document.body.classList.toggle("sidebar-collapsed", collapsed);
    sidebarToggle?.setAttribute("aria-expanded", String(!collapsed));
    const label = sidebarToggle?.querySelector("span");
    if (label) label.textContent = collapsed ? "Развернуть" : "Свернуть";
  };
  if (window.matchMedia("(min-width: 761px)").matches) {
    setSidebarCollapsed(localStorage.getItem(collapsedKey) === "true");
  }
  sidebarToggle?.addEventListener("click", () => {
    const collapsed = !document.body.classList.contains("sidebar-collapsed");
    setSidebarCollapsed(collapsed);
    localStorage.setItem(collapsedKey, String(collapsed));
  });

  const palette = document.getElementById("command-palette");
  const paletteTrigger = document.getElementById("command-palette-trigger");
  const paletteQuery = document.getElementById("command-query");
  const commandEmpty = document.getElementById("command-empty");
  const commandItems = Array.from(document.querySelectorAll("[data-command-item]"));
  let activeCommand = 0;

  const visibleCommands = () => commandItems.filter((item) => !item.hidden);
  const selectCommand = (index) => {
    const visible = visibleCommands();
    if (!visible.length) return;
    activeCommand = (index + visible.length) % visible.length;
    commandItems.forEach((item) => {
      item.classList.remove("current");
      item.setAttribute("aria-selected", "false");
    });
    visible[activeCommand].classList.add("current");
    visible[activeCommand].setAttribute("aria-selected", "true");
    visible[activeCommand].scrollIntoView({ block: "nearest" });
  };
  const filterCommands = () => {
    const query = paletteQuery.value.trim().toLocaleLowerCase("ru");
    commandItems.forEach((item) => {
      const haystack = `${item.textContent} ${item.dataset.keywords || ""}`.toLocaleLowerCase("ru");
      item.hidden = !haystack.includes(query);
    });
    commandEmpty.hidden = visibleCommands().length > 0;
    activeCommand = 0;
    selectCommand(0);
  };
  const openPalette = () => {
    if (!palette?.showModal) return;
    if (!palette.open) palette.showModal();
    paletteQuery.value = "";
    filterCommands();
    window.requestAnimationFrame(() => paletteQuery.focus());
  };
  paletteTrigger?.addEventListener("click", openPalette);
  paletteQuery?.addEventListener("input", filterCommands);
  paletteQuery?.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      selectCommand(activeCommand + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      selectCommand(activeCommand - 1);
    } else if (event.key === "Enter") {
      const selected = visibleCommands()[activeCommand];
      if (selected) {
        event.preventDefault();
        selected.click();
      }
    }
  });
  palette?.addEventListener("click", (event) => {
    if (event.target === palette) palette.close();
  });

  const shortcuts = document.getElementById("shortcuts-dialog");
  document.getElementById("shortcuts-trigger")?.addEventListener("click", () => shortcuts?.showModal());
  shortcuts?.querySelector("[data-dialog-close]")?.addEventListener("click", () => shortcuts.close());
  shortcuts?.addEventListener("click", (event) => {
    if (event.target === shortcuts) shortcuts.close();
  });

  const drawer = document.getElementById("event-detail");
  if (drawer) {
    document.body.classList.add("drawer-open");
    window.requestAnimationFrame(() => drawer.focus());
    document.querySelector("[data-drawer-close]")?.addEventListener("click", (event) => {
      if (event.target !== event.currentTarget) return;
      window.location.assign(event.currentTarget.dataset.closeUrl);
    });
  }

  document.querySelectorAll("[data-detail-url]").forEach((row) => {
    const open = () => window.location.assign(row.dataset.detailUrl);
    row.addEventListener("click", (event) => {
      if (event.target.closest("a, button, input, select, textarea")) return;
      open();
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter") open();
    });
  });

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const source = document.querySelector(button.dataset.copyTarget);
      if (!source) return;
      const value = source.textContent;
      try {
        await navigator.clipboard.writeText(value);
        const previous = button.textContent;
        button.textContent = "Скопировано";
        window.setTimeout(() => { button.textContent = previous; }, 1400);
      } catch {
        button.textContent = "Не удалось скопировать";
      }
    });
  });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-confirm]");
    if (trigger && !window.confirm(trigger.dataset.confirm)) event.preventDefault();
  });
  document.querySelectorAll("[data-job-form]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const submitter = event.submitter;
      if (!submitter || event.defaultPrevented) return;
      window.setTimeout(() => {
        form.setAttribute("aria-busy", "true");
        submitter.textContent = "Отправка…";
        form.querySelectorAll("button").forEach((button) => { button.disabled = true; });
      }, 0);
    });
  });

  const hostStatusLabels = { online: "Онлайн", offline: "Офлайн", degraded: "Нестабильно" };
  const trapStatusLabels = { online: "Онлайн", offline: "Офлайн", pending: "Ожидает", error: "Ошибка", unknown: "Неизвестно" };
  const statusClass = (value) => value === "unknown" ? "neutral" : value;
  const updateStatusPill = (element, value, labels) => {
    if (!element) return;
    element.className = `status-pill status-${statusClass(value)}`;
    element.textContent = labels[value] || "Неизвестно";
  };
  let statusRefreshActive = false;
  const refreshStatusTables = async () => {
    if (statusRefreshActive || document.hidden) return;
    const hostNodes = document.querySelectorAll("[data-host-status-id]");
    const trapNodes = document.querySelectorAll("[data-trap-status-id]");
    if (!hostNodes.length && !trapNodes.length) return;
    statusRefreshActive = true;
    try {
      const requests = [];
      if (hostNodes.length) {
        requests.push(fetch("/api/v1/hosts", { headers: { Accept: "application/json" } })
          .then((response) => response.ok ? response.json() : Promise.reject(new Error(`HTTP ${response.status}`)))
          .then((hosts) => hosts.forEach((host) => {
            updateStatusPill(document.querySelector(`[data-host-status-id="${host.id}"]`), host.status, hostStatusLabels);
            const lastSeen = document.querySelector(`[data-host-last-seen-id="${host.id}"]`);
            if (lastSeen) lastSeen.textContent = formatMoscowTime(host.last_seen_at, "Никогда");
          })));
      }
      if (trapNodes.length) {
        requests.push(fetch("/api/v1/traps", { headers: { Accept: "application/json" } })
          .then((response) => response.ok ? response.json() : Promise.reject(new Error(`HTTP ${response.status}`)))
          .then((traps) => traps.forEach((trap) => {
            updateStatusPill(document.querySelector(`[data-trap-status-id="${trap.id}"]`), trap.status, trapStatusLabels);
            const report = document.querySelector(`[data-trap-report-id="${trap.id}"]`);
            if (report) report.textContent = `Движок: ${trapStatusLabels[trap.reported_status] || "Неизвестно"} · агент: ${hostStatusLabels[trap.host_status] || "Неизвестно"}`;
            const lastSeen = document.querySelector(`[data-trap-last-seen-id="${trap.id}"]`);
            if (lastSeen) lastSeen.textContent = formatMoscowTime(trap.last_seen_at, "Никогда");
          })));
      }
      await Promise.all(requests);
    } catch {
      // Keep the last server-rendered state when a refresh cannot be completed.
    } finally {
      statusRefreshActive = false;
    }
  };
  if (document.querySelector("[data-host-status-id], [data-trap-status-id]")) {
    const statusTimer = window.setInterval(refreshStatusTables, 15000);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) refreshStatusTables();
    });
    window.addEventListener("beforeunload", () => window.clearInterval(statusTimer), { once: true });
  }

  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === "k") {
      event.preventDefault();
      openPalette();
      return;
    }
    if (event.key === "Escape" && (palette?.open || shortcuts?.open)) return;
    if (event.key === "Escape" && drawer) {
      event.preventDefault();
      window.location.assign(drawer.dataset.closeUrl);
      return;
    }
    if (isTyping(event.target)) return;
    if (event.key === "/" && document.body.dataset.page === "/events") {
      event.preventDefault();
      document.querySelector("#event-filters [name='q']")?.focus();
    } else if (event.key === "?") {
      event.preventDefault();
      shortcuts?.showModal();
    }
  });
})();
