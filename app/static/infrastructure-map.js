(() => {
  const nodes = Array.from(document.querySelectorAll("[data-topology-node]"));
  const inspector = document.getElementById("node-inspector");
  if (!nodes.length || !inspector) return;

  const detailKind = document.getElementById("node-detail-kind");
  const detailName = document.getElementById("node-detail-name");
  const detailStatus = document.getElementById("node-detail-status");
  const detailEvents = document.getElementById("node-detail-events");
  const detailActivity = document.getElementById("node-detail-activity");
  const detailOpen = document.getElementById("node-detail-open");
  const detailEventsLink = document.getElementById("node-detail-events-link");

  const selectNode = (node) => {
    nodes.forEach((candidate) => {
      const selected = candidate === node;
      candidate.classList.toggle("is-selected", selected);
      candidate.setAttribute("aria-pressed", String(selected));
    });
    detailKind.textContent = node.dataset.nodeKind || "Узел";
    detailName.textContent = node.dataset.nodeName || "Без имени";
    detailStatus.textContent = node.dataset.nodeStatus || "Нет данных";
    detailEvents.textContent = node.dataset.nodeEvents || "0";
    detailActivity.textContent = node.dataset.nodeLastActivity || "Нет данных";
    detailOpen.href = node.dataset.detailUrl || "/infrastructure";
    const eventsUrl = node.dataset.eventsUrl;
    detailEventsLink.hidden = !eventsUrl;
    if (eventsUrl) detailEventsLink.href = eventsUrl;
  };

  nodes.forEach((node) => {
    node.addEventListener("click", () => selectNode(node));
    node.addEventListener("dblclick", () => {
      window.location.assign(node.dataset.detailUrl || "/infrastructure");
    });
  });
})();
