(() => {
  const form = document.getElementById("event-filters");
  if (!form) return;

  form.addEventListener("submit", () => {
    for (const field of form.elements) {
      if (!field.name || field.type === "submit") continue;
      if (typeof field.value === "string" && field.value.trim() === "") {
        field.disabled = true;
      }
    }
  });
})();
