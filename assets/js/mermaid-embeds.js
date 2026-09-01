import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11.12.0/dist/mermaid.esm.min.mjs";

const diagramBlocks = document.querySelectorAll("pre code.language-mermaid");

if (diagramBlocks.length > 0) {
  const diagrams = [...diagramBlocks].map((code, index) => ({
    index,
    source: code.textContent.trim(),
    element: code.closest(".highlighter-rouge") ?? code.parentElement,
  }));

  async function renderDiagrams() {
    const isDark = document.documentElement.dataset.theme === "dark";

    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      fontFamily: "Inter, ui-sans-serif, sans-serif",
      flowchart: {
        htmlLabels: true,
        useMaxWidth: true,
      },
      themeVariables: {
        background: isDark ? "#1c1c19" : "#ffffff",
        primaryColor: isDark ? "#272724" : "#f7f7f4",
        primaryTextColor: isDark ? "#eeeeea" : "#171716",
        primaryBorderColor: isDark ? "#65655f" : "#a9a9a3",
        lineColor: isDark ? "#a4a49c" : "#686865",
        secondaryColor: isDark ? "#222220" : "#f0f0ec",
        tertiaryColor: isDark ? "#1c1c19" : "#ffffff",
        fontSize: "14px",
      },
    });

    for (const diagramData of diagrams) {
      const { index, source } = diagramData;

      try {
        const renderId = `mermaid-diagram-${index}-${isDark ? "dark" : "light"}`;
        const { svg, bindFunctions } = await mermaid.render(renderId, source);
        const figure = document.createElement("figure");
        const diagram = document.createElement("div");
        const caption = document.createElement("figcaption");

        figure.className = "mermaid-figure";
        diagram.className = "mermaid-embed";
        diagram.innerHTML = svg;
        caption.textContent = "Attack flow diagram";
        figure.append(diagram, caption);

        const renderedSvg = diagram.querySelector("svg");
        renderedSvg?.setAttribute("role", "img");
        renderedSvg?.setAttribute("aria-label", caption.textContent);
        bindFunctions?.(diagram);
        diagramData.element.replaceWith(figure);
        diagramData.element = figure;
      } catch (error) {
        console.error("Unable to render Mermaid diagram.", error);
      }
    }
  }

  await renderDiagrams();
  window.addEventListener("themechange", renderDiagrams);
}