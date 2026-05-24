<p align="center">
  <img src="argos_logo.svg" alt="ARGOS" width="300"/>
</p>

<p align="center"><strong>LLM-orchestrated local penetration testing toolkit for automated vulnerability assessment.</strong></p>

---

## Motivation

Existing LLM-assisted penetration testing tools rely on commercial API endpoints. This means target hostnames, open ports, service banners, and CVE findings are transmitted to third-party infrastructure on every query, and recurring API costs scale with engagement volume.

ARGOS runs entirely on local hardware. The LLM, the embedding model, and all tool execution happen on the operator's machine. No target data leaves the network perimeter at any point.

---

## Operational modes

| Mode | Trigger | What it does |
|------|---------|-------------|
| `nmap` | `--mode nmap --target <ip>` | Full adaptive network pentest: port discovery → service enumeration → NSE scripting → web fuzzing → CVE lookup → Metasploit exploitation → PDF report |
| `debsecan` | `--mode debsecan` | Runs `debsecan` on the local machine, correlates installed packages against NVD, and produces a prioritised CVE report |
| `lynis` | `--mode lynis` | Runs a `lynis` system hardening audit, maps findings to CVEs via NVD, and generates a remediation-focused report |
| `cve` | `--mode cve --cve <id>` | Queries the NVD API for a specific CVE, passes the advisory to the LLM for structured analysis, and returns a concise technical summary |

---

## Architecture overview

ARGOS is structured in three layers:

```
┌─────────────────────────────────────────────────────────┐
│  LLM Planner  (Qwen3-14B via HuggingFace transformers)  │
│  Decides what to do: which scripts, modules, payloads   │
└────────────────────────┬────────────────────────────────┘
                         │ structured JSON plan
┌────────────────────────▼───────────────────────────────────┐
│  RAG Layer (BAAI/bge-small-en-v1.5, sentence-transformers) │
│  Retrieves relevant nmap/MSF documentation; grounds the    │
│  LLM prompt in factual tool reference material             │
└────────────────────────┬───────────────────────────────────┘
                         │ validated commands
┌────────────────────────▼────────────────────────────────┐
│  MCP Execution Servers                                  │
│  nmap · ffuf · msfconsole · NVD API · debsecan · lynis  │
│  Each server validates, sanitises, and executes one tool│
└─────────────────────────────────────────────────────────┘
```

All inference is local. The LLM is loaded once at startup with `device_map="auto"` and runs on GPU if available, CPU otherwise. Embeddings are computed on CPU via `sentence-transformers`. No external AI API is called at any point.

---

## Phase pipeline — nmap mode

| Phase | Name | Description |
|-------|------|-------------|
| 0 | Host check | ICMP + TCP reachability; aborts on unreachable target |
| 1 | Full port scan | SYN scan (`-p-`) to discover all open TCP ports |
| 2 | Service detection | `-sV -sC -O` on discovered ports; output saved as XML |
| 3 | Firewall detection | ACK scan (`-sA`) to identify filtered vs. closed ports |
| 4 | Adaptive NSE | LLM plans per-service script sets (RAG-informed); orchestrator validates and executes |
| 5 | UDP scan | Top-100 UDP ports plus service-specific exploit-focused ports |
| 6 | Web fuzzing | `ffuf` directory and virtual-host enumeration on detected HTTP/HTTPS ports |
| 7 | Evidence aggregation | NVD, CISA KEV, and NSE output merged into ranked CVE entries |
| 7+ | MSF exploitation | LLM selects Metasploit modules; `check → exploit` retry loop; inline post-exploitation |
| — | Reporting | PDF executive report + full plaintext log written to `RESULT/` |

---

## Key design decisions

**Regex-authoritative parsing.** The LLM plans which NSE scripts to run and which Metasploit modules to select, but it never determines which ports or services are present. Port lists and service versions are always extracted from raw nmap XML by regex. The LLM cannot inject a port that the scanner did not find.

**Three-source evidence aggregation.** CVE discovery combines NVD (NIST API queried with CPE strings), CISA KEV (offline catalog with 7-day local cache, token-overlap matching), and NSE script output. The three-source model was introduced specifically to handle CPE slug mismatches where NVD returns nothing for natural-language service strings (e.g. "Microsoft IIS httpd 6.0").

**MSF dry-run safety model.** Before any exploit fires, the Metasploit MCP server runs `check` against the target. A module advances to `exploit` only if `check` confirms vulnerability. Modules that burn the vector on check (vsftpd backdoor, ms08_067, IIS WebDAV) are in a `_NO_CHECK_MODULES` frozenset and bypass this gate.

**Full traceability.** Every CVE finding in the final report links back to the raw tool output that produced it — the nmap XML line, the NSE script output, or the KEV catalog entry. Nothing in the report is inferred without a traceable source.

---

## Tech stack

| Category | Components |
|----------|-----------|
| Language | Python 3.10+ |
| LLM inference | HuggingFace `transformers`, `torch`, `accelerate`, `bitsandbytes` (4-bit quantisation) |
| Embeddings | `sentence-transformers` (BAAI/bge-small-en-v1.5) |
| Report generation | `reportlab`, `fpdf2` |
| Network scanning | `nmap` |
| Web fuzzing | `ffuf` |
| Exploitation | `msfconsole` (Metasploit Framework) |
| Vulnerability search | `searchsploit` (Exploit-DB) |
| Package audit | `debsecan` |
| System audit | `lynis` |
| CVE data | NVD API (NIST), CISA KEV catalog |

---

## Academic context

ARGOS was developed as a final-degree project and is not intended for production use.
