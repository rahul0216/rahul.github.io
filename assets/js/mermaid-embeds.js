import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11.12.0/dist/mermaid.esm.min.mjs";

const diagramBlocks = document.querySelectorAll("pre code.language-mermaid");

if (diagramBlocks.length > 0) {
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
      background: "#ffffff",
      primaryColor: "#f7f7f4",
      primaryTextColor: "#171716",
      primaryBorderColor: "#a9a9a3",
      lineColor: "#686865",
      secondaryColor: "#f0f0ec",
      tertiaryColor: "#ffffff",
      fontSize: "14px",
    },
  });

  for (const [index, code] of [...diagramBlocks].entries()) {
    const source = code.textContent.trim();
    const codeBlock = code.closest(".highlighter-rouge") ?? code.parentElement;

    try {
      const { svg, bindFunctions } = await mermaid.render(`mermaid-diagram-${index}`, source);
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
      codeBlock.replaceWith(figure);
    } catch (error) {
      console.error("Unable to render Mermaid diagram.", error);
    }
  }
}