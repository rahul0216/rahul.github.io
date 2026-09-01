const root = document.documentElement;
const toggle = document.querySelector(".theme-toggle");
const themeColor = document.querySelector('meta[name="theme-color"]');

function applyTheme(theme, persist = false) {
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
  themeColor?.setAttribute("content", theme === "dark" ? "#151513" : "#f7f7f4");

  if (toggle) {
    const nextTheme = theme === "dark" ? "light" : "dark";
    toggle.setAttribute("aria-label", `Switch to ${nextTheme} theme`);
  }

  if (persist) {
    localStorage.setItem("sec-bites-theme", theme);
  }
}

applyTheme(root.dataset.theme ?? "light");

toggle?.addEventListener("click", () => {
  const theme = root.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(theme, true);
  window.dispatchEvent(new CustomEvent("themechange", { detail: { theme } }));
});