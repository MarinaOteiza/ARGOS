"""
generate_doc.py — Generates a technical PDF documenting the Security Toolkit project.
Run:  python3 generate_doc.py
Output: RESULT/SecurityToolkit_Documentation.pdf
"""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, HRFlowable, PageBreak,
    Table, TableStyle, KeepTogether,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.utils import ImageReader

# ── Colour palette ────────────────────────────────────────────────────────────
DARK_BG    = colors.HexColor("#0D1117")
ACCENT     = colors.HexColor("#58A6FF")   # GitHub-blue
GREEN_ACC  = colors.HexColor("#3FB950")
RED_ACC    = colors.HexColor("#F85149")
YELLOW_ACC = colors.HexColor("#D29922")
GREY       = colors.HexColor("#8B949E")
LIGHT_BG   = colors.HexColor("#161B22")
BORDER     = colors.HexColor("#30363D")
WHITE      = colors.white
CODE_BG    = colors.HexColor("#1C2128")

PAGE_W, PAGE_H = A4
MARGIN = 2.0 * cm
CONTENT_W = PAGE_W - 2 * MARGIN

os.makedirs("RESULT", exist_ok=True)
OUT_PATH = "RESULT/SecurityToolkit_Documentation.pdf"

# ── Style sheet ───────────────────────────────────────────────────────────────
styles = getSampleStyleSheet()

def _style(name, **kwargs):
    return ParagraphStyle(name, **kwargs)

ST_TITLE = _style("DocTitle",
    fontName="Helvetica-Bold", fontSize=28, textColor=WHITE,
    alignment=TA_CENTER, spaceAfter=6, leading=34)

ST_SUBTITLE = _style("DocSubtitle",
    fontName="Helvetica", fontSize=13, textColor=ACCENT,
    alignment=TA_CENTER, spaceAfter=4)

ST_META = _style("DocMeta",
    fontName="Helvetica", fontSize=9, textColor=GREY,
    alignment=TA_CENTER, spaceAfter=2)

ST_H1 = _style("H1",
    fontName="Helvetica-Bold", fontSize=18, textColor=ACCENT,
    spaceBefore=18, spaceAfter=8, leading=22)

ST_H2 = _style("H2",
    fontName="Helvetica-Bold", fontSize=13, textColor=GREEN_ACC,
    spaceBefore=12, spaceAfter=5, leading=17)

ST_H3 = _style("H3",
    fontName="Helvetica-Bold", fontSize=11, textColor=YELLOW_ACC,
    spaceBefore=8, spaceAfter=4, leading=14)

ST_BODY = _style("Body",
    fontName="Helvetica", fontSize=9.5, textColor=colors.black,
    alignment=TA_JUSTIFY, spaceAfter=5, leading=14)

ST_BULLET = _style("Bullet",
    fontName="Helvetica", fontSize=9.5, textColor=colors.black,
    spaceAfter=3, leading=13, leftIndent=14, bulletIndent=4)

ST_CODE = _style("Code",
    fontName="Courier", fontSize=8.2, textColor=colors.HexColor("#E6EDF3"),
    backColor=CODE_BG, spaceAfter=4, leading=11,
    leftIndent=10, rightIndent=10)

ST_NOTE = _style("Note",
    fontName="Helvetica-Oblique", fontSize=8.8, textColor=colors.HexColor("#444444"),
    spaceAfter=4, leading=12, leftIndent=8)

ST_CAPTION = _style("Caption",
    fontName="Helvetica-Bold", fontSize=8, textColor=colors.HexColor("#444444"),
    alignment=TA_CENTER, spaceAfter=8)

# Style for text inside dark-background table cells — stays light so it's
# readable against CODE_BG / LIGHT_BG row fills.
ST_CELL = _style("Cell",
    fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#C9D1D9"),
    leading=13, spaceAfter=0)

# ── Helpers ───────────────────────────────────────────────────────────────────

def h1(text): return Paragraph(text, ST_H1)
def h2(text): return Paragraph(text, ST_H2)
def h3(text): return Paragraph(text, ST_H3)
def body(text): return Paragraph(text, ST_BODY)
def note(text): return Paragraph(f"ℹ  {text}", ST_NOTE)
def code(text): return Paragraph(text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"), ST_CODE)
def sp(h=0.3): return Spacer(1, h * cm)
def hr(): return HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6)
def pb(): return PageBreak()

def bullet(text, symbol="•"):
    return Paragraph(f"<bullet>{symbol}</bullet> {text}", ST_BULLET)

def info_table(rows):
    """Two-column label/value table."""
    data = [[Paragraph(f"<b>{k}</b>", ST_CELL), Paragraph(v, ST_CELL)] for k, v in rows]
    t = Table(data, colWidths=[4.5*cm, CONTENT_W - 4.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), LIGHT_BG),
        ("TEXTCOLOR",  (0,0), (0,-1), ACCENT),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [CODE_BG, LIGHT_BG]),
        ("GRID",       (0,0), (-1,-1), 0.4, BORDER),
        ("VALIGN",     (0,0), (-1,-1), "TOP"),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 7),
    ]))
    return t

def phase_table(rows, headers=("Phase", "Name", "Tool", "Description")):
    header_row = [Paragraph(f"<b>{h}</b>", ST_CELL) for h in headers]
    data_rows  = [[Paragraph(str(c), ST_CELL) for c in r] for r in rows]
    t = Table([header_row] + data_rows,
              colWidths=[1.4*cm, 3.2*cm, 2.8*cm, CONTENT_W - 7.4*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), LIGHT_BG),
        ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [CODE_BG, LIGHT_BG]),
        ("GRID",          (0,0), (-1,-1), 0.4, BORDER),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 7),
    ]))
    return t

def cover_block(title_text, subtitle, meta_lines):
    """Dark cover card."""
    inner = [
        Spacer(1, 1.2*cm),
        Paragraph(title_text, ST_TITLE),
        Spacer(1, 0.3*cm),
        Paragraph(subtitle, ST_SUBTITLE),
        Spacer(1, 0.5*cm),
    ]
    for m in meta_lines:
        inner.append(Paragraph(m, ST_META))
    inner.append(Spacer(1, 1.2*cm))
    return inner

def arch_table():
    """Architecture overview table."""
    rows = [
        ["Layer", "Component", "Role"],
        ["Entry", "main.py", "Interactive menu + CLI argument parsing"],
        ["Orchestration", "nmap_orchestrator.py", "7-phase pipeline coordinator"],
        ["Planning", "nmap_planner.py", "LLM-driven NSE script selection"],
        ["RAG – Nmap", "nmap_rag.py", "Script documentation retrieval (cosine similarity)"],
        ["RAG – MSF", "MCP/msf/msf_rag.py", "Module selection via filtered embedding index"],
        ["LLM", "llm_client.py", "Qwen3-14B inference with OOM safety guards"],
        ["Scanning", "MCP/nmap_mcp_server.py", "Subprocess wrapper for nmap"],
        ["CVE Enrichment", "MCP/nmap_nvd_mcp.py", "NIST NVD API queries"],
        ["Web Fuzzing", "MCP/ffuf_mcp.py", "ffuf wrapper with timeout/streaming fixes"],
        ["Exploitation", "MCP/msf/msf_mcp_server.py", "RC script builder + msfconsole runner"],
        ["MSF Planning", "MCP/msf/msf_planner.py", "Module + payload selection"],
        ["MSF Orchestration", "MCP/msf/msf_orchestrator.py", "Exploit execution loop + session handling"],
        ["Phase 7", "MCP/exploit_runner.py", "Searchsploit scripts + default credential checks"],
        ["Reporting", "MCP/nmap_report.py", "PDF report generation (reportlab)"],
        ["Aux – debsecan", "MCP/debsecan_mcp.py", "Local package CVE scanning"],
        ["Aux – lynis", "MCP/lynis_mcp.py", "System audit with NVD enrichment"],
        ["Aux – cve_query", "MCP/cve_query.py", "Direct NVD CVE lookup + LLM analysis"],
    ]
    header = [Paragraph(f"<b>{c}</b>", ST_CELL) for c in rows[0]]
    body_rows = [[Paragraph(c, ST_CELL) for c in r] for r in rows[1:]]
    t = Table([header] + body_rows,
              colWidths=[3.0*cm, 4.5*cm, CONTENT_W - 7.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), LIGHT_BG),
        ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [CODE_BG, LIGHT_BG]),
        ("GRID",          (0,0), (-1,-1), 0.4, BORDER),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 7),
    ]))
    return t

# ── Page template with dark header bar ───────────────────────────────────────

def on_page(canvas, doc):
    canvas.saveState()
    # Header bar
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, PAGE_H - 1.1*cm, PAGE_W, 1.1*cm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(MARGIN, PAGE_H - 0.65*cm, "Security Toolkit — Technical Documentation")
    canvas.setFillColor(GREY)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.65*cm, f"Page {doc.page}")
    # Footer bar
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, 0, PAGE_W, 0.9*cm, fill=1, stroke=0)
    canvas.setFillColor(GREY)
    canvas.setFont("Helvetica", 7)
    canvas.drawCentredString(PAGE_W/2, 0.35*cm,
        "Automated Pentesting Pipeline  ·  LLM + RAG + Metasploit  ·  HTB / Internal Lab Use")
    canvas.restoreState()

# ── Content builder ───────────────────────────────────────────────────────────

def build_story():
    story = []

    # =========================================================================
    # COVER PAGE
    # =========================================================================
    story += cover_block(
        "Security Toolkit",
        "Automated Pentesting Pipeline — LLM + RAG + Metasploit",
        [
            "Author: Marina  ·  Branch: qwen  ·  2026",
            "Kali Linux  ·  Python 3.12  ·  Qwen3-14B (4-bit QLoRA)",
            "Target: HackTheBox / Internal lab environments",
        ]
    )
    story.append(hr())
    story.append(sp(0.4))
    story.append(body(
        "This document describes the full architecture, module-by-module design, and implementation "
        "decisions of an automated penetration testing pipeline. The pipeline drives <b>Nmap</b>, "
        "<b>Metasploit</b>, <b>ffuf</b>, <b>searchsploit</b>, and <b>NVD</b> lookups from a single "
        "entry point, using a locally-hosted <b>Qwen3-14B</b> language model and a "
        "<b>Retrieval-Augmented Generation (RAG)</b> layer to make tool-selection decisions without "
        "hardcoding any target-specific logic."
    ))
    story.append(pb())

    # =========================================================================
    # 1. PROJECT OVERVIEW
    # =========================================================================
    story.append(h1("1. Project Overview"))
    story.append(hr())
    story.append(body(
        "The Security Toolkit is a fully autonomous pentesting assistant designed for use against "
        "HackTheBox machines and internal lab targets. It replaces manual tool chaining with an "
        "AI-driven pipeline that adapts to each target in real time — deciding which scripts to run, "
        "which CVEs to exploit, and which payloads to use based on what it discovers, not from a "
        "fixed playbook."
    ))
    story.append(sp())

    story.append(h2("1.1  Core Design Principles"))
    for p in [
        "<b>No hardcoding.</b> Every decision — from NSE script selection to MSF module choice — is "
        "derived from actual scan output and knowledge-base retrieval, not a target-specific if-else tree.",
        "<b>Deterministic safety nets.</b> The LLM suggests; regex and on-disk validation decide. "
        "Ports only come from nmap output, never from LLM hallucination. Modules only run if they "
        "exist on disk.",
        "<b>Graceful degradation.</b> Every phase is optional. If ffuf is not installed, it is "
        "skipped. If the MSF RAG index is empty, the pipeline falls back to direct NVD CVE data. "
        "If the GPU OOMs, generation retries with smaller token budgets.",
        "<b>GPU-safe LLM inference.</b> Qwen3-14B runs locally in 4-bit QLoRA. Prompts are "
        "truncated before reaching the model, KV-cache is flushed between calls, and OOM is "
        "retried automatically.",
        "<b>Unified PDF output.</b> Every phase appends its findings to a structured session log "
        "that is rendered into a single PDF at the end of the run.",
    ]:
        story.append(bullet(p))
    story.append(sp())

    story.append(h2("1.2  Operational Modes"))
    rows = [
        ("nmap",     "Remote network pentest — the main 7-phase pipeline"),
        ("debsecan", "Local Debian package CVE scan + NVD enrichment"),
        ("lynis",    "Local system audit (CIS hardening) + NVD enrichment"),
        ("cve",      "Direct NVD CVE lookup + LLM explanation"),
    ]
    story.append(info_table(rows))
    story.append(sp())

    story.append(h2("1.3  Technology Stack"))
    rows2 = [
        ("LLM",        "Qwen3-14B via HuggingFace transformers (local, 4-bit QLoRA)"),
        ("Embeddings", "BAAI/bge-small-en-v1.5 via sentence-transformers (CPU)"),
        ("Scanning",   "nmap ≥ 7.92 with full NSE script library"),
        ("Exploitation","Metasploit Framework (msfconsole) via RC resource scripts"),
        ("Web fuzzing", "ffuf with common.txt / SecLists wordlists"),
        ("CVE data",   "NIST NVD REST API v2 (with optional API key)"),
        ("Searchsploit","ExploitDB local database (searchsploit CLI)"),
        ("PDF output", "reportlab 4.x"),
        ("OS",         "Kali Linux (Debian-based), Python 3.12"),
    ]
    story.append(info_table(rows2))
    story.append(pb())

    # =========================================================================
    # 2. SYSTEM ARCHITECTURE
    # =========================================================================
    story.append(h1("2. System Architecture"))
    story.append(hr())
    story.append(body(
        "The pipeline follows a layered architecture. The orchestrator drives the phases; "
        "the planner decides what to do next; the RAG layers provide domain knowledge without "
        "needing the LLM to memorise thousands of module details; the MCP servers wrap each tool "
        "so the rest of the code never builds shell commands directly."
    ))
    story.append(sp(0.4))

    story.append(h2("2.1  Component Map"))
    story.append(arch_table())
    story.append(sp())

    story.append(h2("2.2  Data Flow"))
    story.append(body(
        "The nmap pipeline runs as a sequential loop of phases. Each phase appends its "
        "output to <b>accumulated_findings</b> (a list of dicts held by NmapPlanner). "
        "The planner's <b>_consolidated_findings()</b> merges all findings into one "
        "authoritative view before any decision is made."
    ))
    story.append(sp(0.2))
    flow = [
        ("Phase 0", "Full TCP SYN scan (-p-)", "nmap", "Discover all open ports"),
        ("Phase 1", "Version + OS detection (-sV -sC)", "nmap + XML", "Build service inventory"),
        ("Phase 2", "Firewall detection (ACK scan)", "nmap", "Detect filtering"),
        ("Phase 3", "Adaptive NSE scanning (LLM-planned)", "LLM + RAG + nmap", "Script-level enumeration"),
        ("Phase 4", "UDP scan (top 50)", "nmap", "Discover UDP services"),
        ("Phase 5", "Web fuzzing", "ffuf", "Directory + vhost discovery"),
        ("Phase 6", "Metasploit exploitation", "MSF + LLM + RAG", "Exploit confirmed CVEs"),
        ("Phase 7", "Searchsploit + credentials", "searchsploit / paramiko", "Alternative exploitation"),
    ]
    story.append(phase_table(flow))
    story.append(sp())

    story.append(h2("2.3  Hybrid Architecture: RAG provides knowledge, LLM provides reasoning"))
    story.append(body(
        "The key architectural insight is the separation of <i>knowledge</i> from <i>reasoning</i>. "
        "The RAG retrieves relevant documentation chunks (what each NSE script does; what each MSF "
        "module targets). The LLM reads those chunks and outputs structured JSON decisions. "
        "The orchestrator validates and executes. This lets a 14B model perform accurately without "
        "hallucinating commands, because it never writes raw shell strings — only JSON."
    ))
    story.append(pb())

    # =========================================================================
    # 3. ENTRY POINT — main.py
    # =========================================================================
    story.append(h1("3. Entry Point — main.py"))
    story.append(hr())
    story.append(body(
        "main.py is the single user-facing entry point. It handles both an interactive "
        "menu and full CLI argument parsing, then delegates to the appropriate orchestrator."
    ))
    story.append(sp(0.3))
    story.append(h2("3.1  Responsibilities"))
    for p in [
        "Terminal mode restoration — fixes TTY after msfconsole leaves it in raw mode (termios ICRNL/ONLCR).",
        "Dependency checking — verifies nmap, ffuf, debsecan, lynis are on PATH; warns but continues.",
        "Mode dispatch — routes to NmapOrchestrator, debsecan_mcp, lynis_mcp, or cve_query.",
        "CLI flags — --target, --dry-run, --nvd-key, --mode, --only-fixed, --no-sudo, etc.",
    ]:
        story.append(bullet(p))
    story.append(sp(0.3))
    story.append(h2("3.2  Usage Examples"))
    story.append(code("python3 main.py                                    # interactive menu"))
    story.append(code("python3 main.py --mode nmap --target 10.10.10.56   # direct pentest"))
    story.append(code("python3 main.py --mode debsecan --only-fixed        # local CVE scan"))
    story.append(code("python3 main.py --mode lynis --nvd-key YOUR_KEY     # system audit"))
    story.append(pb())

    # =========================================================================
    # 4. LLM CLIENT — llm_client.py
    # =========================================================================
    story.append(h1("4. LLM Client — llm_client.py"))
    story.append(hr())
    story.append(body(
        "llm_client.py is the single interface to the language model. All other modules "
        "call only two functions from here: <b>chat()</b> for text generation and "
        "<b>get_embedding()</b> for vector embeddings. Everything about GPU safety, "
        "quantization, and OOM recovery is encapsulated here."
    ))
    story.append(sp(0.3))

    story.append(h2("4.1  Model Loading"))
    story.append(body(
        "The model loads once at first call and is cached in the global <b>_llm_pipe</b>. "
        "On CUDA-capable systems with ≥ 10.5 GB free VRAM, the model is loaded in "
        "<b>4-bit NF4 QLoRA</b> (bitsandbytes). Otherwise it falls back to bfloat16 on CPU."
    ))
    story.append(sp(0.2))
    for p in [
        "<b>Model:</b> Qwen/Qwen3-14B (~7 GB in 4-bit, ~28 GB in bfloat16).",
        "<b>Embeddings:</b> BAAI/bge-small-en-v1.5 always on CPU to avoid competing with the LLM for VRAM.",
        "<b>Flash Attention 2:</b> enabled automatically if flash-attn is installed — reduces VRAM ~30% on long sequences.",
        "<b>NF4 double quantization:</b> bnb_4bit_use_double_quant=True quantizes the quantization constants, saving ~0.4 bits/parameter.",
    ]:
        story.append(bullet(p))
    story.append(sp(0.3))

    story.append(h2("4.2  GPU Safety Layers"))
    story.append(body(
        "Several independent layers prevent the GPU from running out of memory or crashing:"
    ))
    story.append(sp(0.1))
    safety_rows = [
        ("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True — allocator reuses freed VRAM blocks instead of reserving new ones, preventing fragmentation"),
        ("_cuda_free()", "Called before AND after every generation: gc.collect() + torch.cuda.empty_cache() flushes unreferenced KV-cache tensors"),
        ("Prompt truncation", "_MAX_PROMPT_TOKENS = 6144: prompts longer than this are truncated from the LEFT (newest content kept) before being sent to the model. Prevents prefill OOM."),
        ("OOM retry loop", "If generation throws OutOfMemoryError, max_tokens is halved and generation retries up to 3 times"),
        ("del output", "After extracting text, the output tensor is explicitly deleted before _cuda_free() to free memory immediately"),
    ]
    story.append(info_table(safety_rows))
    story.append(sp(0.3))

    story.append(h2("4.3  Inference Parameters"))
    story.append(code("chat(messages, temperature=0.3, max_tokens=1024)"))
    story.append(body(
        "Temperature 0.3 is used for planning/analysis (some diversity). "
        "Temperature 0.1 is used for module selection (near-deterministic). "
        "enable_thinking=False suppresses Qwen3's chain-of-thought &lt;think&gt; blocks "
        "for faster, cleaner output. Any residual &lt;think&gt; blocks are stripped by regex."
    ))
    story.append(pb())

    # =========================================================================
    # 5. RAG LAYER — nmap_rag.py
    # =========================================================================
    story.append(h1("5. Nmap RAG Layer — nmap_rag.py"))
    story.append(hr())
    story.append(body(
        "The Nmap RAG provides the LLM planner with relevant NSE script documentation "
        "at plan time. Without it the LLM must recall script behaviour from training data "
        "alone, which leads to incoherent selections (e.g. smtp scripts on SSH ports). "
        "With it, the LLM reads accurate, specific documentation and makes much better choices."
    ))
    story.append(sp(0.3))

    story.append(h2("5.1  Document Source"))
    story.append(body(
        "INFO/nmap_manual.txt contains concatenated output of: the nmap man page, "
        "all NSE script documentation blocks, and the most important scan flags. "
        "It is built once and chunked into segments of ≤ 900 characters."
    ))
    story.append(sp(0.2))
    story.append(h2("5.2  Indexing Pipeline"))
    for p in [
        "<b>load_chunks():</b> splits nmap_manual.txt by script/flag sections using regex. Each NSE script becomes one chunk prefixed with 'Script NSE: scriptname.nse'.",
        "<b>build_index():</b> embeds every chunk with BAAI/bge-small-en-v1.5. Result: list of {chunk, embedding} dicts. Saved as .pkl with model-tag for cache invalidation.",
        "<b>load_index():</b> validates the stored model tag against the current EMBED_MODEL. Rebuilds automatically if they differ.",
    ]:
        story.append(bullet(p))
    story.append(sp(0.2))

    story.append(h2("5.3  Service-Aware Retrieval"))
    story.append(body(
        "retrieve_for_services() is the main integration point. For each discovered service "
        "it constructs multiple queries (e.g. 'NSE scripts for vsftpd 2.3.4', "
        "'NSE scripts for FTP anonymous access backdoor') and retrieves the top-N chunks "
        "by cosine similarity. Chunks with similarity &lt; 0.3 are discarded. "
        "Results are deduplicated across services and injected into the planner prompt."
    ))
    story.append(pb())

    # =========================================================================
    # 6. NMAP PLANNER — nmap_planner.py
    # =========================================================================
    story.append(h1("6. Nmap Planner — nmap_planner.py"))
    story.append(hr())
    story.append(body(
        "NmapPlanner is the brain of the scanning phase. It maintains all accumulated "
        "findings, plans the next batch of scan steps using the LLM, and analyzes "
        "nmap output to extract ports, services, and vulnerability indicators."
    ))
    story.append(sp(0.3))

    story.append(h2("6.1  Findings Accumulation"))
    story.append(body(
        "Every nmap execution appends a findings dict to <b>accumulated_findings</b>. "
        "<b>_consolidated_findings()</b> merges them: regex-extracted data always wins "
        "over LLM data. Port lists are unioned; service strings are upgraded to longer "
        "(more specific) versions when later scans provide better detail."
    ))
    story.append(sp(0.2))

    story.append(h2("6.2  Regex Safety Nets (CRIT fixes)"))
    story.append(body(
        "The LLM analyzes nmap output for insights, but the authoritative data always "
        "comes from regex:"
    ))
    story.append(sp(0.1))
    for p in [
        "<b>CRIT-001:</b> _regex_extract_ports() is the sole authority for port numbers. LLM ports not confirmed by regex are rejected.",
        "<b>CRIT-002:</b> Port-service coherence check — _validate_port_service() rejects incoherent assignments (e.g. smtp-scripts on port 22).",
        "<b>CRIT-003:</b> Regex versions always override LLM versions in service strings.",
        "<b>FIX-NSE:</b> NSE script output is parsed in a second pass to upgrade generic service strings (e.g. 'http' → 'Apache httpd 2.4.18') using http-title and http-server-header output.",
    ]:
        story.append(bullet(p))
    story.append(sp(0.2))

    story.append(h2("6.3  Script Findings Extraction"))
    story.append(body(
        "_regex_extract_script_findings() extracts vulnerability indicators directly "
        "from NSE output without relying on the LLM:"
    ))
    story.append(sp(0.1))
    for p in [
        "Anonymous FTP login detected.",
        "SMB signing status and guest authentication.",
        "distcc RCE (CVE-2004-2687) confirmation.",
        "vsftpd 2.3.4 backdoor confirmation.",
        "Samba version strings (for CVE-2007-2447 matching).",
        "<b>Shellshock:</b> any line containing 'cve-2014-6271' in the NSE section fires the finding.",
        "<b>CGI paths:</b> http-enum output like '/cgi-bin/user.sh: Shell file' is extracted and stored as 'CGI script found on port N: /path'.",
    ]:
        story.append(bullet(p))
    story.append(sp(0.2))

    story.append(h2("6.4  Deterministic Vulnerability Knowledge Base (_KNOWN_VULNS)"))
    story.append(body(
        "_KNOWN_VULNS is a list of rules, each with a service_re (regex matched against "
        "the version string), severity, CVE ID, title, and Metasploit module path. "
        "generate_deterministic_recommendations() runs two passes:"
    ))
    story.append(sp(0.1))
    story.append(bullet(
        "<b>Pass 1:</b> Match service_re against each service string "
        "(e.g. r'vsftpd\\s+2\\.3\\.4' matches 'vsftpd 2.3.4')."
    ))
    story.append(bullet(
        "<b>Pass 2:</b> Match service_re against each interesting_finding string. "
        "This is how Shellshock fires — the rule has service_re r'shellshock|cve-2014-6271' "
        "which matches the finding 'shellshock CVE-2014-6271 detected on port 80', "
        "not the service string 'apache httpd 2.4.18'."
    ))
    story.append(sp(0.1))
    story.append(body(
        "OS-matching guards prevent cross-platform mistakes: Windows modules are skipped "
        "on Linux targets (has_samba → is_linux) and vice versa."
    ))
    story.append(sp(0.2))

    story.append(h2("6.5  Known Vulnerabilities Covered"))
    kb_rows = [
        ("CVE-2011-2523", "vsftpd 2.3.4 backdoor", "CRITICAL", "exploit/unix/ftp/vsftpd_234_backdoor"),
        ("CVE-2007-2447", "Samba 3.0.x username map RCE", "CRITICAL", "exploit/multi/samba/usermap_script"),
        ("CVE-2017-0143", "EternalBlue MS17-010", "CRITICAL", "exploit/windows/smb/ms17_010_eternalblue"),
        ("CVE-2008-4250", "MS08-067 netapi RCE", "CRITICAL", "exploit/windows/smb/ms08_067_netapi"),
        ("CVE-2014-6271", "Shellshock Bash CGI RCE", "CRITICAL", "exploit/multi/http/apache_mod_cgi_bash_env_exec"),
        ("CVE-2021-41773", "Apache 2.4.49 path traversal RCE", "CRITICAL", "exploit/multi/http/apache_normalize_path_rce"),
        ("CVE-2004-2687", "distcc unauthenticated RCE", "HIGH", "exploit/unix/misc/distcc_exec"),
        ("CVE-2019-0708", "BlueKeep RDP pre-auth RCE", "CRITICAL", "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"),
        ("CVE-2018-15473", "OpenSSH username enumeration", "MEDIUM", "auxiliary/scanner/ssh/ssh_enumusers"),
        ("CVE-2017-7494", "SambaCry EternalRed RCE", "HIGH", "exploit/linux/samba/is_known_pipename"),
        ("CVE-2019-10149", "Exim 4.87-4.91 RCE", "CRITICAL", "exploit/unix/smtp/exim4_string_format"),
    ]
    header = [Paragraph(f"<b>{h}</b>", ST_CELL) for h in ("CVE", "Vulnerability", "Severity", "MSF Module")]
    data = [[Paragraph(c, ST_CELL) for c in r] for r in kb_rows]
    t = Table([header] + data,
              colWidths=[2.8*cm, 4.5*cm, 2.0*cm, CONTENT_W - 9.3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), LIGHT_BG),
        ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [CODE_BG, LIGHT_BG]),
        ("GRID",          (0,0), (-1,-1), 0.4, BORDER),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 7),
    ]))
    story.append(t)
    story.append(pb())

    # =========================================================================
    # 7. NMAP ORCHESTRATOR — nmap_orchestrator.py
    # =========================================================================
    story.append(h1("7. Nmap Orchestrator — nmap_orchestrator.py"))
    story.append(hr())
    story.append(body(
        "NmapOrchestrator is the main controller for the 7-phase pipeline. "
        "It holds all state (session_log, nvd_data, msf_findings), "
        "coordinates every phase in order, and generates the final PDF report."
    ))
    story.append(sp(0.3))

    story.append(h2("7.1  Phase 0 — Full TCP Discovery"))
    story.append(body(
        "Runs nmap -sS -p- --min-rate 1000. This SYN scan covers all 65535 ports "
        "and is the authoritative source for open ports. Every later scan uses only "
        "ports discovered here."
    ))
    story.append(sp(0.2))

    story.append(h2("7.2  Phase 1 — Version Detection"))
    story.append(body(
        "Runs nmap -sV --version-intensity 5 -sC -oX on the discovered ports. "
        "The XML output is parsed by _parse_nmap_xml() to extract structured "
        "(product, version, CPE) tuples per port, which are used directly in NVD queries "
        "rather than relying on regex-parsed service strings."
    ))
    story.append(sp(0.2))

    story.append(h2("7.3  Phase 2 — Firewall Detection"))
    story.append(body(
        "ACK scan (-sA). Ports that are open in Phase 0 but filtered in the ACK scan "
        "indicate a stateful firewall. These filtered ports are excluded from all "
        "subsequent scanning."
    ))
    story.append(sp(0.2))

    story.append(h2("7.4  Phase 3 — Adaptive NSE Scanning"))
    story.append(body(
        "The core intelligence phase. Runs up to 5 rounds of LLM-planned scanning. "
        "Each round: consolidated findings → RAG retrieves script docs → LLM outputs "
        "structured JSON {steps: [{port, scripts, reason}]} → orchestrator validates "
        "and builds nmap commands. The LLM never writes raw nmap commands."
    ))
    story.append(sp(0.1))
    story.append(note(
        "Script coherence validation ensures HTTP scripts only run on HTTP ports, "
        "SMB scripts only on 139/445, etc. Scripts not on disk are rejected even if "
        "the LLM suggests them."
    ))
    story.append(sp(0.2))

    story.append(h2("7.5  Phase 4 — UDP Scan"))
    story.append(body(
        "nmap -sU --top-ports 50. Discovers common UDP services (DNS/53, SNMP/161, "
        "NTP/123, TFTP/69). Results feed into the NVD enrichment and service inventory."
    ))
    story.append(sp(0.2))

    story.append(h2("7.6  Phase 5 — Web Fuzzing (ffuf)"))
    story.append(body(
        "_collect_http_ports() identifies HTTP ports using three signals: NSE proved "
        "HTTP (http-title fired), well-known HTTP port numbers, service string keywords. "
        "For each HTTP port, ffuf runs directory fuzzing and vhost fuzzing. "
        "Results are logged and fed into the PDF."
    ))
    story.append(sp(0.1))
    story.append(note(
        "ffuf uses common.txt first (fast), timeout=300s, streams output via Popen "
        "(not capture_output) to prevent false 'hanging' appearances."
    ))
    story.append(sp(0.2))

    story.append(h2("7.7  Phase 6 — Metasploit Exploitation"))
    story.append(body(
        "_run_msf_phase() builds scan_results from consolidated findings + NVD CVEs "
        "+ deterministic recommendations, then delegates to MsfOrchestrator. "
        "The MSF phase runs only if at least one CVE was found."
    ))
    story.append(sp(0.2))

    story.append(h2("7.8  Phase 7 — Searchsploit + Default Credentials"))
    story.append(body(
        "exploit_runner.run_phase() runs two parallel tracks: "
        "Track A tries searchsploit exploit scripts for each CVE; "
        "Track B checks SSH/FTP/HTTP Basic Auth against a list of default credentials."
    ))
    story.append(pb())

    # =========================================================================
    # 8. MSF SUBSYSTEM
    # =========================================================================
    story.append(h1("8. Metasploit Subsystem — MCP/msf/"))
    story.append(hr())
    story.append(body(
        "The MSF subsystem is a self-contained package that handles the full exploitation "
        "lifecycle: RAG-based module selection, RC script generation, execution, output "
        "parsing, session detection, and interactive session handoff."
    ))
    story.append(sp(0.3))

    story.append(h2("8.1  msf_rag.py — Module Selection RAG"))
    story.append(body(
        "Builds a per-target embedding index from three sources:"
    ))
    story.append(sp(0.1))
    for p in [
        "<b>Source 1 — searchsploit:</b> Queries searchsploit --json for each CVE, adds formatted exploit entries as chunks.",
        "<b>Source 2 — msfconsole search:</b> For CVEs with CVSS ≥ 7.0, runs 'msfconsole -x search cve:NNNN-NNNNN' and fetches full module info chunks via 'use module; info'.",
        "<b>Source 3 — msf_manual.txt:</b> A pre-built text file of all MSF module summaries is filtered to only chunks matching the target OS/services. This keeps the index from growing to 4000+ chunks.",
    ]:
        story.append(bullet(p))
    story.append(sp(0.1))
    story.append(body(
        "ask() retrieves top-N chunks by cosine similarity (with CVE-ID priority pass) "
        "and prompts the LLM to select a module + options as JSON. "
        "OS-specific guidance in the prompt helps the model distinguish "
        "EternalBlue (Win7/2008) vs ms08_067_netapi (XP/2003)."
    ))
    story.append(sp(0.2))

    story.append(h2("8.2  msf_planner.py — Plan Generation"))
    story.append(body(
        "generate_plan() iterates over CVEs sorted by CVSS descending. "
        "For each CVE it takes one of two paths:"
    ))
    story.append(sp(0.1))
    story.append(bullet(
        "<b>Fast path:</b> CVE has msf_module set (from _KNOWN_VULNS KB). "
        "Skips RAG/LLM entirely. Also merges msf_options (e.g. TARGETURI for Shellshock)."
    ))
    story.append(bullet(
        "<b>RAG path:</b> Queries msf_rag.ask(). Validates module on disk. "
        "If the LLM picks a non-existent path, scans RAG context chunks for real exploit/ paths."
    ))
    story.append(sp(0.1))
    story.append(body(
        "_select_payload() picks the correct payload deterministically based on OS/arch. "
        "It reads the module's .rb file to detect DefaultPayload and CmdStager. "
        "CmdStager modules (like apache_mod_cgi_bash_env_exec) get native Linux "
        "meterpreter payloads, not cmd/unix/reverse_perl."
    ))
    story.append(sp(0.2))

    story.append(h2("8.3  msf_mcp_server.py — RC Script Builder + Executor"))
    story.append(body(
        "_build_rc() generates a msfconsole resource script (.rc) for each plan entry. "
        "Key decisions made here:"
    ))
    story.append(sp(0.1))
    for p in [
        "<b>Handler strategy:</b> Meterpreter/Windows-shell payloads use a background multi/handler (run -j) started BEFORE the exploit. CMD-type payloads (reverse_perl, reverse_bash) use the module's inline handler. This prevents race conditions on fast Windows shellcode.",
        "<b>WfsDelay:</b> Set to 30s only for inline handlers. Background-handler modules keep WfsDelay at the module default (e.g. 5s for EternalBlue) so jobs -K completes quickly.",
        "<b>SMB port fallback:</b> If an SMB module times out on port 445, it automatically retries on port 139, and vice versa. This is critical for Windows XP (Legacy) which often has 445 filtered on HTB.",
        "<b>_NO_CHECK_MODULES:</b> Modules whose 'check' command would trigger the exploit (vsftpd backdoor) or hang (ms08_067_netapi) skip the check phase entirely.",
        "<b>_MODULE_DEFAULTS:</b> Required options with no MSF default (e.g. TARGETURI for Shellshock, TARGET index) are applied automatically.",
        "<b>Generic option emission:</b> Any extra options (TARGETURI, TARGET, etc.) in the plan entry are emitted as 'set KEY VALUE' lines via _extra_option_lines().",
    ]:
        story.append(bullet(p))
    story.append(sp(0.2))

    story.append(h2("8.4  Output Parsing"))
    story.append(body(
        "_parse_output() scans msfconsole stdout for five outcome classes:"
    ))
    story.append(sp(0.1))
    for pair in [
        ("session_opened", "Regex matches 'Meterpreter session N opened' or 'Command shell session N opened'"),
        ("vulnerable", "Phrase match: 'The target appears to be vulnerable'"),
        ("check_unavailable", "'Cannot reliably check' or ConnectionTimeout → proceed to exploit anyway"),
        ("error", "Rex::ConnectionRefused, HostUnreachable → target not reachable, stop"),
        ("no_result", "None of the above — module ran but produced nothing conclusive"),
    ]:
        story.append(bullet(f"<b>{pair[0]}:</b> {pair[1]}"))
    story.append(sp(0.1))
    story.append(note(
        "TimeoutExpired rescues partial output: exc.stdout is decoded as bytes "
        "(even with text=True) so it can still be parsed for session indicators."
    ))
    story.append(pb())

    # =========================================================================
    # 9. NVD ENRICHMENT — nmap_nvd_mcp.py
    # =========================================================================
    story.append(h1("9. NVD Enrichment — MCP/nmap_nvd_mcp.py"))
    story.append(hr())
    story.append(body(
        "After all scanning phases, enrich_with_nvd() queries the NIST NVD REST API v2 "
        "for CVEs affecting each discovered service. The results feed directly into the "
        "MSF planner as additional exploit targets."
    ))
    story.append(sp(0.3))
    for p in [
        "<b>CPE-first queries:</b> If nmap XML provided a CPE string (e.g. cpe:/a:vsftpd:vsftpd:2.3.4), it queries NVD by CPE — this is the most accurate method.",
        "<b>Keyword fallback:</b> For services without CPE data, queries by 'product version' keyword string.",
        "<b>Rate limiting:</b> Without an API key, NVD allows 5 requests/30s. The code sleeps between requests. With an API key, rate limit is 50 requests/30s.",
        "<b>CVSS scoring:</b> Returns CVSS v3.1 score preferred, falls back to v2. Scores used to prioritise exploitation order.",
        "<b>String normalisation:</b> LLM may return plain CVE ID strings instead of dicts; these are normalised to {cve_id, score, url, port} dicts before use.",
    ]:
        story.append(bullet(p))
    story.append(pb())

    # =========================================================================
    # 10. WEB FUZZING — ffuf_mcp.py
    # =========================================================================
    story.append(h1("10. Web Fuzzing — MCP/ffuf_mcp.py"))
    story.append(hr())
    story.append(body(
        "FFUFServer wraps the ffuf web fuzzer. The key design decision is to stream "
        "output via Popen rather than capture_output=True — ffuf writes progress to "
        "stderr in real time, and capture_output causes the process to appear frozen "
        "for the entire duration of the scan."
    ))
    story.append(sp(0.3))
    for p in [
        "<b>Wordlist priority:</b> common.txt first (fast, ~4k entries), then directory-list-2.3-medium.txt, then big.txt. Wordlists are discovered by searching SecLists installation paths.",
        "<b>Timeout:</b> DEFAULT_TIMEOUT = 300s. Partial results are rescued on TimeoutExpired.",
        "<b>Concurrent threads:</b> -t 40 (balanced — high enough to be fast, low enough to not trigger WAF rate limiting on HTB).",
        "<b>Output format:</b> JSON (-of json) to a temp file; parsed after the run for structured results.",
        "<b>Vhost scanning:</b> A separate ffuf run per HTTP port uses -H 'Host: FUZZ.hostname' to discover virtual hosts.",
        "<b>Recursion:</b> 301/302 responses trigger a recursive scan into the redirected directory (capped at 3 directories).",
    ]:
        story.append(bullet(p))
    story.append(pb())

    # =========================================================================
    # 11. EXPLOIT RUNNER — exploit_runner.py
    # =========================================================================
    story.append(h1("11. Exploit Runner — MCP/exploit_runner.py"))
    story.append(hr())
    story.append(body(
        "Phase 7 of the pipeline. Runs independently of Metasploit and handles two "
        "complementary attack vectors: standalone exploit scripts from ExploitDB "
        "and default credential attacks."
    ))
    story.append(sp(0.3))

    story.append(h2("11.1  Track A — Searchsploit Scripts"))
    for p in [
        "_searchsploit_query() calls searchsploit --json and returns matching exploit entries.",
        "_is_runnable() filters to standalone scripts (.py, .sh, .rb, .pl) of type 'remote' or 'webapps'. MSF wrappers are excluded.",
        "_copy_exploit() copies the script to a temp directory via 'searchsploit -m EDB-ID'.",
        "_try_run() attempts 8 common invocation patterns (target only, target+port, URL, -t flag, etc.) with a 25s timeout per attempt.",
        "_looks_like_shell() checks the output for shell prompt indicators: '$', '#', 'uid=', 'root@', 'sh-N.N$'.",
    ]:
        story.append(bullet(p))
    story.append(sp(0.2))

    story.append(h2("11.2  Track B — Default Credentials"))
    for p in [
        "<b>SSH:</b> _is_ssh_banner() does a raw socket check first — reads the first 64 bytes and verifies the response starts with 'SSH-'. This prevents paramiko from connecting to non-SSH ports and printing transport-thread exceptions to stderr. paramiko logging is set to CRITICAL.",
        "<b>FTP:</b> ftplib.FTP.login() with each credential pair. Timeout = 6s.",
        "<b>HTTP Basic Auth:</b> First probes without credentials — if the response is 200, the endpoint is not auth-protected and the check is skipped (avoids false positives on open Apache defaults). Only tries credentials after confirming a 401 challenge.",
    ]:
        story.append(bullet(p))
    story.append(pb())

    # =========================================================================
    # 12. AUXILIARY MODES
    # =========================================================================
    story.append(h1("12. Auxiliary Modes"))
    story.append(hr())

    story.append(h2("12.1  debsecan_mcp.py — Local Package CVE Scanner"))
    story.append(body(
        "Runs debsecan to list all CVEs affecting installed Debian packages. "
        "Enriches results with NVD CVSS scores. Generates a PDF report ranked by severity. "
        "Supports --only-fixed to show only CVEs with available patches."
    ))
    story.append(sp(0.2))

    story.append(h2("12.2  lynis_mcp.py — System Audit"))
    story.append(body(
        "Runs lynis audit system and parses the structured log file (/var/log/lynis.log). "
        "Extracts warnings, suggestions, and hardening index. Enriches each finding with "
        "NVD data where a CVE applies. Generates a PDF with CIS benchmark alignment."
    ))
    story.append(sp(0.2))

    story.append(h2("12.3  cve_query.py — Direct CVE Lookup"))
    story.append(body(
        "Queries NVD directly by CVE ID or product keyword. Runs the result through "
        "the LLM for a plain-English analysis of impact, affected versions, and "
        "recommended remediation. Useful for rapid vulnerability research without "
        "running a full scan."
    ))
    story.append(pb())

    # =========================================================================
    # 13. REPORT GENERATION — nmap_report.py
    # =========================================================================
    story.append(h1("13. Report Generation — MCP/nmap_report.py"))
    story.append(hr())
    story.append(body(
        "generate_reports() produces a single PDF combining all phases of the pentest: "
        "scan findings, NVD CVEs, MSF exploitation results, ffuf discoveries, and the "
        "LLM executive summary. Output path: RESULT/pentest_IP_TIMESTAMP.pdf."
    ))
    story.append(sp(0.3))
    for p in [
        "Cover page with target, timestamp, and summary statistics.",
        "Phase-by-phase scan output with highlighted findings.",
        "CVE table sorted by CVSS score (CRITICAL first).",
        "Metasploit results: module, status (session_opened / vulnerable / no_result), captured getuid / sysinfo output.",
        "ffuf directory listing and vhost discoveries.",
        "Deterministic recommendations table (from _KNOWN_VULNS KB).",
        "LLM executive report (the 4-section markdown report rendered into the PDF).",
        "Phase timing breakdown.",
    ]:
        story.append(bullet(p))
    story.append(pb())

    # =========================================================================
    # 14. KEY BUGS FIXED
    # =========================================================================
    story.append(h1("14. Key Engineering Decisions & Bugs Fixed"))
    story.append(hr())
    story.append(body(
        "The following table records the most significant non-obvious fixes made "
        "during development. Each represents a case where the correct behaviour was "
        "not obvious from the code alone."
    ))
    story.append(sp(0.3))

    bugs = [
        ("Legacy (XP) SMB port fallback",
         "Windows XP on HTB has port 445 filtered but 139 reachable. "
         "Added _SMB_PORT_FALLBACKS {445→139, 139→445}. On Rex::ConnectionTimeout "
         "for an SMB module, the orchestrator retries on the other port and mutates "
         "the RPORT in-place so the interactive session uses the correct port."),
        ("_ERROR_STRINGS ordering",
         "EternalBlue output contains both 'Rex::ConnectionTimeout' and 'Exploit failed'. "
         "If 'Exploit failed' was checked first, ConnectionTimeout was hidden and the "
         "port-139 retry never triggered. Fix: Rex:: errors are checked BEFORE the "
         "generic 'Exploit failed' wrapper."),
        ("WfsDelay for background-handler modules",
         "EternalBlue has WfsDelay=>5 in its .rb. Overriding it to 30 kept the exploit "
         "job running after the session opened, causing 'jobs -K' to hang until "
         "MODULE_TIMEOUT. Fix: WfsDelay is only set for inline-handler modules."),
        ("TimeoutExpired.stdout is bytes",
         "subprocess with text=True returns str from stdout on success, but "
         "TimeoutExpired.stdout is always bytes. Added _dec() helper that isinstance-checks "
         "before decoding."),
        ("LAME: handler strategy split",
         "Restoring the background handler for all payloads broke LAME. "
         "cmd/unix/reverse_perl is slow — the inline handler has time to start. "
         "Background handler + DisablePayloadHandler=true broke usermap_script's "
         "own handler. Fix: background handler only for meterpreter / Windows-shell payloads."),
        ("Shellshock: two-pass KB matching",
         "The Shellshock KB rule has service_re r'shellshock|cve-2014-6271' which "
         "never matches a service string like 'apache httpd 2.4.18'. The detection "
         "comes from the NSE http-shellshock script, which writes the CVE ID into "
         "interesting_findings. Fix: generate_deterministic_recommendations() added "
         "a second pass matching rules against individual findings strings."),
        ("Shellshock: TARGETURI required",
         "apache_mod_cgi_bash_env_exec requires TARGETURI (no default in MSF). "
         "Fix: http-enum CGI paths are extracted into findings by _regex_extract_script_findings(). "
         "_build_scan_results() looks up the CGI path from findings and passes it as "
         "msf_options={TARGETURI: '/cgi-bin/user.sh'}. _MODULE_DEFAULTS provides the "
         "hardcoded fallback. _extra_option_lines() emits all non-standard options."),
        ("CmdStager payload selection",
         "apache_mod_cgi_bash_env_exec uses Msf::Exploit::CmdStager (needs native "
         "linux/x64 payload) but the planner matched it to the exploit/multi/ prefix "
         "and returned cmd/unix/reverse_perl. Fix: _get_default_payload() detects "
         "'Msf::Exploit::CmdStager' in the .rb file and returns linux/x64/meterpreter/reverse_tcp."),
        ("ffuf appearing to hang",
         "subprocess.run(capture_output=True) holds ffuf's stderr buffer until completion. "
         "ffuf writes progress bars to stderr — the buffer fill makes the process appear "
         "frozen for 30+ minutes. Fix: Popen with stdout=None streams output live. "
         "Timeout reduced from 3600s to 300s."),
        ("SSH banner exceptions in paramiko",
         "paramiko's transport thread prints 'Exception (client): Error reading SSH protocol "
         "banner' to stderr even when the caller catches SSHException. Fix: raw-socket "
         "banner pre-check (_is_ssh_banner) skips paramiko entirely for non-SSH ports. "
         "paramiko logger set to CRITICAL."),
        ("LLM prefill OOM not covered by retry",
         "The OOM retry loop only catches generation-phase OutOfMemoryError. A very long "
         "prompt OOMs during prefill before generation starts — the retry never fires. "
         "Fix: prompt is tokenised and truncated to _MAX_PROMPT_TOKENS=6144 before "
         "being passed to the pipeline."),
        ("ms08_067_netapi 'No matching target'",
         "When MSF cannot auto-detect the Windows version it prints 'No matching target'. "
         "This string was missing from _ERROR_STRINGS so it mapped to 'no_result' "
         "instead of 'error'. Fix: added 'No matching target' and 'No target matched' "
         "to _ERROR_STRINGS."),
    ]

    for title, desc in bugs:
        story.append(KeepTogether([
            h3(f"▸  {title}"),
            body(desc),
            sp(0.2),
        ]))

    story.append(pb())

    # =========================================================================
    # 15. CONFIRMED WORKING MACHINES
    # =========================================================================
    story.append(h1("15. Confirmed Exploitation Results — HTB Machines"))
    story.append(hr())
    story.append(body(
        "The following HackTheBox machines have been successfully exploited by the "
        "automated pipeline without any manual intervention after starting the run."
    ))
    story.append(sp(0.3))

    machines = [
        ("Legacy (10.10.10.4)", "Windows XP SP3", "CVE-2008-4250 MS08-067",
         "exploit/windows/smb/ms08_067_netapi", "Port 139 (445 filtered). Auto SMB fallback."),
        ("LAME (10.10.10.3)", "Linux / Samba 3.0.20", "CVE-2007-2447",
         "exploit/multi/samba/usermap_script", "Inline handler. Also distcc_exec (CVE-2004-2687)."),
        ("Blue (10.10.10.40)", "Windows 7 SP1", "CVE-2017-0143 EternalBlue",
         "exploit/windows/smb/ms17_010_eternalblue", "Background handler. Session via partial output rescue."),
        ("Shocker (10.10.10.56)", "Ubuntu 16.04", "CVE-2014-6271 Shellshock",
         "exploit/multi/http/apache_mod_cgi_bash_env_exec", "TARGETURI=/cgi-bin/user.sh, TARGET=1 (x64), CmdStager payload."),
    ]

    header = [Paragraph(f"<b>{h}</b>", ST_CELL)
              for h in ("Machine", "OS", "CVE", "MSF Module", "Notes")]
    data = [[Paragraph(c, ST_CELL) for c in r] for r in machines]
    t = Table([header] + data,
              colWidths=[2.8*cm, 2.5*cm, 2.8*cm, 4.5*cm, CONTENT_W - 12.6*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), LIGHT_BG),
        ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [CODE_BG, LIGHT_BG]),
        ("GRID",          (0,0), (-1,-1), 0.4, BORDER),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 7),
    ]))
    story.append(t)
    story.append(sp(0.5))

    story.append(h2("Machines in Progress"))
    for p in [
        "<b>Optimum (Windows / HFS 2.3b):</b> CVE-2014-6287 detected. ffuf fixes allow web fuzzing to complete. Exploitation pending.",
        "<b>Devel (Windows / IIS 7.5 FTP):</b> Anonymous FTP detected, web shell upload route identified.",
        "<b>Nibbles (Linux / Nibbleblog):</b> Web application identified via http-title. ffuf finds /nibbleblog/admin.php.",
    ]:
        story.append(bullet(p))
    story.append(pb())

    # =========================================================================
    # 16. RUNNING THE PIPELINE
    # =========================================================================
    story.append(h1("16. Running the Pipeline"))
    story.append(hr())

    story.append(h2("16.1  Dependencies"))
    story.append(code("pip install transformers torch accelerate bitsandbytes sentence-transformers"))
    story.append(code("pip install reportlab paramiko"))
    story.append(code("sudo apt install nmap ffuf metasploit-framework exploitdb"))
    story.append(sp(0.3))

    story.append(h2("16.2  Environment"))
    story.append(code("# .env file in the project root\nHF_API_KEY=your_huggingface_token   # optional for public models\nNVD_KEY=your_nvd_api_key             # optional, increases NVD rate limit"))
    story.append(sp(0.3))

    story.append(h2("16.3  Quickstart"))
    story.append(code("cd /path/to/pentestM/RAG\npython3 main.py --mode nmap --target 10.10.10.56"))
    story.append(sp(0.1))
    story.append(body(
        "The pipeline will warm up the LLM, run all 7 phases, and produce a PDF in RESULT/. "
        "The entire run for a typical HTB machine takes 15–45 minutes depending on GPU speed "
        "and number of open ports."
    ))
    story.append(sp(0.3))

    story.append(h2("16.4  Dry-Run Mode"))
    story.append(code("python3 main.py --mode nmap --target 10.10.10.56 --dry-run"))
    story.append(body(
        "In dry-run mode, nmap commands are executed but MSF runs 'check' instead of 'run'. "
        "No exploit is fired, but the full plan is generated and validated."
    ))

    return story


# ── Build PDF ─────────────────────────────────────────────────────────────────

def main():
    print(f"Building documentation PDF → {OUT_PATH}")
    doc = SimpleDocTemplate(
        OUT_PATH,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.5*cm, bottomMargin=1.2*cm,
        title="Security Toolkit — Technical Documentation",
        author="Marina",
        subject="Automated Pentesting Pipeline LLM+RAG+Metasploit",
    )

    story = build_story()
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    size_kb = os.path.getsize(OUT_PATH) // 1024
    print(f"Done — {OUT_PATH}  ({size_kb} KB)")


if __name__ == "__main__":
    main()
