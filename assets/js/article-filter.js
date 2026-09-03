(() => {
  const tools = document.querySelector(".research-tools");
  const cards = [...document.querySelectorAll(".article-card")];

  if (!tools || cards.length === 0) return;

  const buttons = [...tools.querySelectorAll("[data-category]")];
  const search = tools.querySelector("#article-search");
  const count = document.querySelector("#research-count");
  const emptyResults = document.querySelector(".empty-results");
  let activeCategory = "all";

  const updateResults = () => {
    const query = search.value.trim().toLowerCase();
    let visibleCount = 0;

    cards.forEach((card) => {
      const categoryMatches = activeCategory === "all" || card.dataset.category === activeCategory;
      const searchMatches = card.dataset.search.includes(query);
      const isVisible = categoryMatches && searchMatches;

      card.hidden = !isVisible;
      visibleCount += Number(isVisible);
    });

    count.textContent = `${visibleCount} ${visibleCount === 1 ? "report" : "reports"}`;
    emptyResults.hidden = visibleCount !== 0;
  };

  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      activeCategory = button.dataset.category;
      buttons.forEach((item) => {
        const isActive = item === button;
        item.classList.toggle("is-active", isActive);
        item.setAttribute("aria-pressed", isActive);
      });
      updateResults();
    });
  });

  search.addEventListener("input", updateResults);
  tools.hidden = false;
})();