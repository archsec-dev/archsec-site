---
title: "OWASP Top 10 for LLMs & Agentic AI: Visual Attack Map & Code Defenses"
linkTitle: "OWASP LLM & Agentic Attack Map"
weight: 4
description: "Visual attack-surface map and code-level defenses for OWASP Top 10 for LLM Applications and Agentic AI systems."
slug: owasp-llm-agentic-top10-infographic
date: 2026-11-12T10:00:00+05:30
draft: false
tags: ["OWASP Top 10 LLM", "Agentic AI", "AI Security", "Infographic", "Zero-Trust AI", "Defense in Depth"]
keywords: ["OWASP LLM Top 10 infographic", "OWASP Agentic AI attack map", "LLM security code defenses", "AI security architecture"]
---

*A visual reference mapping LLM and autonomous agent threat surfaces to concrete architectural and code-level controls across `learn.archsec.dev`.*

---

## Visual Attack Surface & Defense Map

<figure class="archsec-viewer">
  <div class="archsec-viewer-bar">
    <div class="archsec-zoom-group" role="group" aria-label="Diagram zoom controls">
      <button type="button" id="svg-zoom-out" class="archsec-zbtn" title="Zoom out">&minus;</button>
      <span id="svg-zoom-label" class="archsec-zlabel">100%</span>
      <button type="button" id="svg-zoom-in" class="archsec-zbtn" title="Zoom in">+</button>
      <button type="button" id="svg-zoom-reset" class="archsec-zbtn archsec-zbtn-muted">Reset</button>
    </div>
    <a href="/images/owasp-llm-agentic-top10-infographic.svg" target="_blank" rel="noopener" class="archsec-open-link">Open Full SVG &nearr;</a>
  </div>
  <div id="archsec-viewer-stage" class="archsec-viewer-stage">
    <img
      id="archsec-owasp-svg"
      src="/images/owasp-llm-agentic-top10-infographic.svg"
      alt="OWASP Top 10 for LLMs and Agentic AI visual attack map and defense architecture"
      class="archsec-viewer-img"
    />
  </div>
  <figcaption class="archsec-viewer-caption">
    OWASP Top 10 (LLM &amp; Agentic AI) threat flow and defense-in-depth control map. Use + / &minus; to inspect details.
  </figcaption>
</figure>

<style>
  .archsec-viewer {
    margin: 1.5rem 0;
    width: 100%;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 10px;
    overflow: hidden;
  }
  .archsec-viewer-bar {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
    padding: 0.55rem 0.85rem;
    background: #1e293b;
    border-bottom: 1px solid #334155;
  }
  .archsec-zoom-group {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
  }
  .archsec-zbtn {
    cursor: pointer;
    background: #0f172a;
    color: #f8fafc;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 0.2rem 0.6rem;
    font-size: 0.85rem;
    font-weight: 700;
    line-height: 1.3;
    transition: border-color 0.15s ease, background 0.15s ease;
  }
  .archsec-zbtn:hover {
    border-color: #38bdf8;
    background: #172554;
  }
  .archsec-zbtn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .archsec-zbtn-muted {
    font-size: 0.75rem;
    font-weight: 600;
    color: #94a3b8;
    margin-left: 0.2rem;
  }
  .archsec-zlabel {
    min-width: 3.2rem;
    text-align: center;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.8rem;
    font-weight: 700;
    color: #38bdf8;
  }
  .archsec-open-link {
    font-size: 0.78rem;
    font-weight: 600;
    color: #38bdf8;
    text-decoration: none;
  }
  .archsec-open-link:hover {
    text-decoration: underline;
  }
  .archsec-viewer-stage {
    width: 100%;
    overflow: auto;
    max-height: 78vh;
    background: #090d16;
  }
  .archsec-viewer-img {
    display: block;
    width: 100%;
    max-width: none;
    height: auto;
    transition: width 0.15s ease;
  }
  .archsec-viewer-caption {
    font-size: 0.82rem;
    color: #94a3b8;
    padding: 0.6rem 0.85rem;
    background: #0f172a;
    border-top: 1px solid #1e293b;
    text-align: center;
  }
</style>

<script>
(function () {
  const img = document.getElementById("archsec-owasp-svg");
  const label = document.getElementById("svg-zoom-label");
  const btnIn = document.getElementById("svg-zoom-in");
  const btnOut = document.getElementById("svg-zoom-out");
  const btnReset = document.getElementById("svg-zoom-reset");

  let zoom = 100;
  const MIN_ZOOM = 75;
  const MAX_ZOOM = 250;
  const STEP = 25;

  function updateZoom() {
    img.style.width = zoom + "%";
    label.textContent = zoom + "%";
    btnOut.disabled = zoom <= MIN_ZOOM;
    btnIn.disabled = zoom >= MAX_ZOOM;
  }

  btnIn.addEventListener("click", () => {
    if (zoom < MAX_ZOOM) {
      zoom += STEP;
      updateZoom();
    }
  });

  btnOut.addEventListener("click", () => {
    if (zoom > MIN_ZOOM) {
      zoom -= STEP;
      updateZoom();
    }
  });

  btnReset.addEventListener("click", () => {
    zoom = 100;
    updateZoom();
  });

  updateZoom();
})();
</script>

---

## Code-Level Defenses Across the Blueprint Series

Pair this visual map with the full architectural blueprints and runnable code in the series:

| Trust Boundary / Risk Area | Primary Blueprint | Core Code-Level Control |
| :--- | :--- | :--- |
| **Autonomous Agent Identity & Memory** | [Part 1: Securing Autonomous AI Agents](/ai-security/securing-autonomous-ai-agents/) | Session taint propagation, memory write-barriers, SPIFFE workload identities, RFC 8693 token exchange, and HITL gates |
| **MCP Tool Manifests, Auth & Path Escapes** | [Part 2: Securing the Model Context Protocol (MCP)](/ai-security/securing-model-context-protocol-mcp/) | Canonical SHA-256 manifest pinning against rug pulls, RFC 8707 audience (`aud`) validation, `os.path.realpath` containment, and rootless sandboxes |
| **Prompt Injection & Untrusted Context** | [Part 3: Defending RAG Indirect Prompt Injection](/ai-security/defending-rag-indirect-prompt-injection/) | HTML/CSS/Unicode sanitization, classifier gating, per-request Spotlighting delimiters, and Dual-LLM schema extraction |
| **Sensitive Data & Egress Exfiltration** | [Part 3: Defending RAG Indirect Prompt Injection](/ai-security/defending-rag-indirect-prompt-injection/) | Document-level ACL filtering, Markdown image stripping (`![...](...)`), and domain-allowlisted hyperlink validation |