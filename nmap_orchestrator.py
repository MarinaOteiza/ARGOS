"""
nmap_orchestrator.py — Adaptive pentest orchestrator: RAG informs, LLM chooses, orchestrator builds.

HYBRID ARCHITECTURE:
  Phase 0-2: Fixed discovery steps (always the same, no LLM needed)
  Phase 3:   RAG retrieves script documentation for discovered services
             → LLM reads docs + findings → outputs structured JSON (port, scripts, reason)
             → Orchestrator validates scripts on disk → builds correct nmap command
  Phase 4:   UDP scan (fixed)
  Phase 5:   ffuf web fuzzing (deterministic, excludes filtered ports)

The RAG provides KNOWLEDGE (what each NSE script does, from nmap_manual.txt)
The LLM provides REASONING (which scripts fit this specific target)
The orchestrator provides EXECUTION (correct nmap syntax, always)
"""

import argparse
import os
import sys
import time
import re
import textwrap
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from nmap_planner import NmapPlanner, validate_scripts

try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    load_dotenv(dotenv_path=_env_path)
except ImportError:
    pass

def check_tool(tool: str) -> bool:
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

try:
    from nmap_planner         import NmapPlanner, validate_scripts, _detect_service_category
    from MCP.nmap_mcp_server  import MCPServer
    from MCP.nmap_nvd_mcp     import enrich_with_nvd, merge_nse_cves, _parse_service_string_generic
    from MCP.nmap_report      import generate_reports
    from MCP.ffuf_mcp         import (FFUFServer, build_ffuf_command, find_wordlist,
                                      find_vhost_wordlist)
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

# Evidence aggregator + KEV — optional, degrade gracefully
try:
    from MCP.evidence_aggregator import build_extra_cve_entries
    from MCP.kev_client          import KevClient
    EVIDENCE_AGGREGATOR_AVAILABLE = True
except ImportError:
    EVIDENCE_AGGREGATOR_AVAILABLE = False

# RAG is optional — graceful degradation if not available
try:
    import nmap_rag
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

# MSF is optional — only available if metasploit + msf_* modules are installed
try:
    from MCP.msf.msf_orchestrator import MsfOrchestrator
    from MCP.msf.msf_rag import build_target_index as msf_build_index
    MSF_AVAILABLE = True
except ImportError:
    MSF_AVAILABLE = False

# Searchsploit + credential runner — optional, degrades gracefully
try:
    from MCP.exploit_runner import run_phase as exploit_runner_run
    EXPLOIT_RUNNER_AVAILABLE = True
except ImportError:
    EXPLOIT_RUNNER_AVAILABLE = False

MAX_ROUNDS      = 5
MAX_STEPS_TOTAL = 25
NMAP_TXT        = "INFO/nmap_manual.txt"
INDEX_CACHE     = "INFO/nmap_index.pkl"

# ──────────────────────────────────────────────────────────────────────────────
# Terminal helpers
# ──────────────────────────────────────────────────────────────────────────────

BOLD   = "\033[1m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
RESET  = "\033[0m"

W = 66   # consistent terminal width

def _justify_para(text: str, width: int = W) -> str:
    """Full-justify plain text: pad inner lines to `width`, last line left-aligned."""
    wrapped = textwrap.wrap(text, width)
    result = []
    for i, ln in enumerate(wrapped):
        words = ln.split()
        if i == len(wrapped) - 1 or len(words) <= 1:
            result.append(ln)
        else:
            spare = width - sum(len(w) for w in words)
            gaps  = len(words) - 1
            q, r  = divmod(spare, gaps)
            parts = [words[0]]
            for j in range(gaps):
                parts.append(' ' * (q + (1 if j < r else 0)))
                parts.append(words[j + 1])
            result.append(''.join(parts))
    return '\n'.join(result) if result else text


_BULLET_RE   = re.compile(r'^(\s*)[*\-]\s+(.*)')
_NUMBERED_RE = re.compile(r'^(\s*)(\d+)\.\s+(.*)')


def _render_markdown(text: str) -> str:
    def _inline(s: str) -> str:
        s = re.sub(r'\*\*(.+?)\*\*', f'{BOLD}\\1{RESET}', s)
        s = re.sub(r'`([^`\n]+)`',   f'{CYAN}\\1{RESET}', s)
        return s

    out      = []
    in_code  = False
    code_buf: list[str] = []

    def _flush_code():
        nonlocal code_buf
        if not code_buf:
            return
        inner_w = W - 6                        # 2 indent + │ + space + space + │
        out.append(f"  {DIM}┌{'─' * (W - 4)}┐{RESET}")
        for cl in code_buf:
            out.append(f"  {DIM}│{RESET} {GREEN}{cl.ljust(inner_w)}{RESET} {DIM}│{RESET}")
        out.append(f"  {DIM}└{'─' * (W - 4)}┘{RESET}")
        code_buf = []

    for line in text.split("\n"):
        stripped = line.strip()

        # ── Code fence (``` or `): toggle mode ──────────────────────
        if re.match(r'^`{1,3}\w*$', stripped):
            if not in_code:
                in_code  = True
                code_buf = []
            else:
                in_code = False
                _flush_code()
            continue

        if in_code:
            code_buf.append(stripped)
            continue

        # ── Empty line ───────────────────────────────────────────────
        if not stripped:
            out.append("")
            continue

        # ── Horizontal rule ──────────────────────────────────────────
        if stripped in ("---", "***", "___"):
            out.append(f"  {DIM}{'─' * 58}{RESET}")
            continue

        # ── Headings ─────────────────────────────────────────────────
        if stripped.startswith("### "):
            out.append(f"{BOLD}{_inline(stripped[4:])}{RESET}")
            continue
        if stripped.startswith("## "):
            out.append(f"\n{BOLD}{_inline(stripped[3:])}{RESET}")
            continue
        if stripped.startswith("# "):
            out.append(f"\n{BOLD}{CYAN}{_inline(stripped[2:])}{RESET}")
            continue

        # ── Bullet (any indent level) ─────────────────────────────────
        m = _BULLET_RE.match(line)
        if m:
            depth  = len(m.group(1)) // 2
            prefix = "  " + "  " * depth + "• "
            out.append(f"{prefix}{_inline(m.group(2))}")
            continue

        # ── Numbered list (any indent level) ─────────────────────────
        m = _NUMBERED_RE.match(line)
        if m:
            depth  = len(m.group(1)) // 2
            prefix = "  " * (depth + 1)
            out.append(f"{prefix}{BOLD}{m.group(2)}.{RESET}  {_inline(m.group(3))}")
            continue

        # ── Regular paragraph: justify then apply inline styles ───────
        out.append(_inline(_justify_para(stripped, W)))

    if in_code:
        _flush_code()

    return "\n".join(out)

def header(title: str):
    bar = "─" * W
    print(f"\n{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{bar}{RESET}")

def step_banner(n: int, label: str):
    print(f"\n{BOLD}  ▸ Step {n}  ·  {label}{RESET}")
    print(f"  {DIM}{'─' * 54}{RESET}")

def info(t: str):    print(f"  {CYAN}·{RESET}  {t}")
def warn(t: str):    print(f"  {YELLOW}⚠{RESET}  {t}")
def success(t: str): print(f"  {GREEN}✓{RESET}  {t}")
def error(t: str):   print(f"  {RED}✗{RESET}  {t}")

def output_block(text: str, max_lines: int = 25):
    lines = text.strip().split("\n")
    for line in lines[:max_lines]:
        print(f"  {DIM}{line}{RESET}")
    if len(lines) > max_lines:
        print(f"  {DIM}  … +{len(lines) - max_lines} lines{RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# Command building helpers (orchestrator writes commands, never the LLM)
# ──────────────────────────────────────────────────────────────────────────────

_SUDO_FLAGS = frozenset({"-sS", "-sA", "-sF", "-sX", "-sN", "-sU", "-sO", "-O", "--traceroute"})

def _ensure_sudo(cmd):
    # /usr/lib/nmap/nmap has cap_net_raw,cap_net_admin,cap_net_bind_service=eip,
    # and the /usr/bin/nmap wrapper adds --privileged for non-root users automatically.
    # Adding sudo is counter-productive in non-interactive shells (no password prompt).
    # Strip any existing sudo prefix so commands run directly with nmap capabilities.
    if cmd.startswith("sudo "):
        return cmd[5:]
    return cmd

def _clean_port(port):
    try:
        return int(str(port).replace("/tcp", "").replace("/udp", "").strip())
    except (ValueError, TypeError):
        return None

HTTP_WELL_KNOWN = frozenset({80, 443, 8080, 8443, 8000, 8008, 8888, 9090, 3000, 5000})
HTTP_KEYWORDS   = frozenset({
    "http", "https", "ssl/http", "gunicorn", "nginx", "apache", "flask",
    "tornado", "iis", "lighttpd", "node", "jetty", "tomcat", "werkzeug",
    "uvicorn", "caddy", "web", "golang", "express", "rails", "puma",
    "spring", "fastapi", "django",
})


def build_nmap_command(step: dict, target_ip: str) -> str:
    """
    Build a valid nmap command from a structured step dict.
    This is where ALL command synthesis happens — never in the LLM.
    """
    scan_type = step.get("scan_type", "nse_scripts")
    port = step.get("port")
    scripts = step.get("scripts", [])

    if scan_type == "udp_scan":
        return f"nmap -Pn -sU --top-ports 50 --open --max-retries 1 {target_ip}"

    if scan_type == "vuln_scan":
        port_flag = f"-p {port}" if port else ""
        return f"nmap -Pn -sV --script vuln {port_flag} {target_ip} --script-timeout 30s"

    if scan_type == "version_detect":
        port_flag = f"-p {port}" if port else "--top-ports 1000"
        return f"nmap -Pn -sV {port_flag} {target_ip}"

    # nse_scripts (default)
    if not scripts:
        scripts = ["banner"]
    scripts_str = ",".join(scripts)
    port_flag = f"-p {port}" if port else ""
    return f"nmap -Pn -sV --script {scripts_str} {port_flag} {target_ip} --script-timeout 30s"


# ──────────────────────────────────────────────────────────────────────────────
# PUSH NOTIFICATION — ntfy.sh
# ──────────────────────────────────────────────────────────────────────────────

_NTFY_TOPIC = "pentestM_TFG_mo"

def _notify_done(target_ip: str, elapsed: float, steps: int, msf_findings: dict):
    """Send a push notification to the configured ntfy.sh topic."""
    sessions = sum(1 for r in msf_findings.get("results", []) if r.get("session_opened"))
    mins, secs = divmod(int(elapsed), 60)
    status = f"{sessions} session(s) opened" if sessions else "no sessions"
    message = (
        f"Target: {target_ip}\n"
        f"Duration: {mins}m {secs:02d}s  ({steps} steps)\n"
        f"Result: {status}"
    )
    try:
        req = urllib.request.Request(
            f"https://ntfy.sh/{_NTFY_TOPIC}",
            data=message.encode("utf-8"),
            method="POST",
        )
        req.add_header("Content-Type", "text/plain; charset=utf-8")
        req.add_header("Title",    f"Pentest done - {target_ip}")
        req.add_header("Priority", "high")
        req.add_header("Tags",     "shield,checkered_flag")
        urllib.request.urlopen(req, timeout=8)
        print(f"  Notification sent to ntfy ({_NTFY_TOPIC})")
    except Exception as e:
        print(f"  Notification failed (ntfy): {e}")


# ──────────────────────────────────────────────────────────────────────────────
# ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────

class NmapOrchestrator:

    def __init__(self, target_ip, objetivo="", dry_run=False, nvd_api_key=""):
        self.target_ip   = target_ip
        self.objetivo    = objetivo
        self.dry_run     = dry_run
        self.nvd_api_key = nvd_api_key
        self.planner     = NmapPlanner()
        self.mcp         = MCPServer(dry_run=dry_run)
        self.ffuf        = FFUFServer(dry_run=dry_run)
        self.total_steps = 0
        self.start_time  = None
        self.session_log   = []
        self.nvd_data      = []
        self.phase_timings: list[dict] = []   # [{name, duration_s, steps}]
        self.msf_findings: dict = {}           # MSF results for unified PDF
        self.exploit_runner_findings: dict = {}  # Phase 7 searchsploit + cred results
        self._executed     = set()
        self._executed_ffuf = set()
        self._nmap_xml_path  = None
        self._msf_orch       = None
        self._detected_arch  = ""   # populated from nmap -O CPE/osmatch
        self.searchsploit_results: dict = {}   # {port_str|"os": [raw exploit entries]}
        self._syn_confirmed_open: set   = set()  # ports confirmed open by Phase 0 SYN scan

    # ── State helpers ─────────────────────────────────────────────

    def _normalize_cmd(self, cmd):
        import shlex
        try:
            parts = shlex.split(cmd)
            ignore = {"--reason", "--open", "--version-intensity",
                      "--script-timeout", "30s", "60s", "10s", "-Pn", "--host-timeout"}
            tokens = [p for p in parts[1:]
                      if p != self.target_ip and p not in ignore
                      and not re.match(r'^\d+s$', p)]
            return "nmap " + " ".join(sorted(tokens))
        except Exception:
            return cmd.strip().lower()

    def _get_open_ports(self):
        ports = set()
        for f in self.planner.accumulated_findings:
            for p in f.get("open_ports", []):
                c = _clean_port(p)
                if c: ports.add(c)
        return sorted(ports)

    def _get_services(self):
        services = {}
        for f in self.planner.accumulated_findings:
            for pk, svc in f.get("services", {}).items():
                p = _clean_port(pk)
                if p is None: continue
                incoming = str(svc).strip()
                current = services.get(p, "")
                if not current or current.lower() in ("unknown", "ssh", "http", "ftp", ""):
                    if incoming and incoming.lower() not in ("unknown", ""):
                        services[p] = incoming
                elif len(incoming) > len(current):
                    services[p] = incoming
        return services

    def _get_filtered(self):
        open_set = set(self._get_open_ports())
        filtered = set()
        for f in self.planner.accumulated_findings:
            for p in f.get("filtered_ports", []):
                c = _clean_port(p)
                if c and c not in open_set:
                    filtered.add(c)
        return filtered
    
    def _get_nse_meta(self) -> dict[int, dict]:
        """Aggregate nse_meta from all accumulated findings."""
        merged: dict[int, dict] = {}
        for f in self.planner.accumulated_findings:
            for port, meta in f.get("nse_meta", {}).items():
                port_int = _clean_port(port)
                if port_int is None:
                    continue
                if port_int not in merged:
                    merged[port_int] = dict(meta)
                else:
                    existing = merged[port_int]
                    if meta.get("http_title") and not existing.get("http_title"):
                        existing["http_title"] = meta["http_title"]
                    if meta.get("server_header") and not existing.get("server_header"):
                        existing["server_header"] = meta["server_header"]
                    if meta.get("is_http"):
                        existing["is_http"] = True
                    existing.setdefault("nse_lines", []).extend(meta.get("nse_lines", []))
        return merged

    def _parse_nmap_xml(self) -> dict[str, dict]:
        """
        Extract structured (product, version, cpe) per port from nmap XML.
        Also reads <os> elements from -O output to detect architecture from CPE
        or osmatch name ("64-bit" / "32-bit"), storing it in self._detected_arch.
        Returns {port_str: {"product": ..., "version": ..., "cpe": ...}}
        """
        xml_path = self._nmap_xml_path
        if not xml_path or not os.path.isfile(xml_path):
            return {}
        try:
            tree = ET.parse(xml_path)
            services = {}
            for port_el in tree.findall(".//port"):
                port_id = port_el.get("portid")
                state = port_el.find("state")
                if state is not None and state.get("state") != "open":
                    continue
                svc = port_el.find("service")
                if svc is not None:
                    product = svc.get("product", "")
                    version = svc.get("version", "")
                    cpe_el = svc.find("cpe")
                    cpe = cpe_el.text if cpe_el is not None else ""
                    services[port_id] = {
                        "product": product,
                        "version": version,
                        "cpe": cpe,
                    }

            # Detect architecture from -O OS fingerprint data.
            # CPE component 6 (cpe:/o:vendor:product:version:update:arch)
            # e.g. cpe:/o:microsoft:windows_7::sp1:x64 → x64
            # Fallback: osmatch name may contain "64-bit" or "32-bit".
            for cpe_el in tree.findall(".//os//cpe"):
                cpe_text = (cpe_el.text or "").strip()
                parts = cpe_text.split(":")
                if len(parts) >= 7:
                    arch_tok = parts[6].lower()
                    if arch_tok in ("x64", "amd64", "x86_64"):
                        self._detected_arch = "x86_64"; break
                    if arch_tok in ("x86", "i386", "i686"):
                        self._detected_arch = "x86";    break
            if not self._detected_arch:
                for match_el in tree.findall(".//os//osmatch"):
                    name = (match_el.get("name") or "").lower()
                    if "64-bit" in name or "x64" in name or "amd64" in name:
                        self._detected_arch = "x86_64"; break
                    if "32-bit" in name or "x86" in name or "i386" in name:
                        self._detected_arch = "x86";    break

            # Final fallback: known pre-x64-era Windows OS names are 32-bit
            # by default.  nmap's osmatch for these targets ("Microsoft Windows
            # Server 2003 SP2", "Microsoft Windows XP SP3") never includes a
            # "32-bit" suffix nor an arch token in the CPE, so the loops above
            # leave _detected_arch empty and the orchestrator falls back to
            # x86_64 — which produces an x64 payload against an x86 target.
            if not self._detected_arch:
                _X86_ONLY_OS = (
                    "windows xp", "windows server 2003", "windows server 2000",
                    "windows 2000", "windows nt", "windows 9", "windows me",
                )
                for match_el in tree.findall(".//os//osmatch"):
                    name = (match_el.get("name") or "").lower()
                    if any(s in name for s in _X86_ONLY_OS):
                        self._detected_arch = "x86"
                        break
                if not self._detected_arch:
                    for cpe_el in tree.findall(".//os//cpe"):
                        cpe_text = (cpe_el.text or "").lower()
                        if any(s.replace(" ", "_") in cpe_text for s in _X86_ONLY_OS):
                            self._detected_arch = "x86"
                            break

            arch_note = f" · arch={self._detected_arch}" if self._detected_arch else ""
            info(f"XML parsed: {len(services)} services with structured product/version{arch_note}")
            return services
        except Exception as e:
            warn(f"XML parse error: {e}")
            return {}

    def _ports_str(self, default="22,80,443"):
        ports = self._get_open_ports()
        return ",".join(str(p) for p in ports) if ports else default

    # ── RAG initialization ────────────────────────────────────────

    def _init_rag(self):
        """Load RAG index and pass it to the planner for script documentation retrieval."""
        if not RAG_AVAILABLE:
            warn("RAG module not available — planner will use static script catalog only.")
            return

        info("Loading RAG index for script documentation...")
        try:
            if os.path.exists(INDEX_CACHE):
                rag_index = nmap_rag.load_index(INDEX_CACHE)
            elif os.path.exists(NMAP_TXT):
                info("Building RAG index from scratch (first run)...")
                chunks = nmap_rag.load_chunks(NMAP_TXT)
                rag_index = nmap_rag.build_index(chunks)
                nmap_rag.save_index(rag_index, INDEX_CACHE)
            else:
                warn(f"RAG source not found: {NMAP_TXT}")
                return

            self.planner.set_rag_index(rag_index)
            success(f"RAG active: {len(rag_index)} script documentation chunks loaded.")
            info("LLM will receive relevant script docs when planning each scan step.")
        except Exception as e:
            warn(f"RAG init failed: {e} — planner will use static catalog only.")

    # ── Step execution ────────────────────────────────────────────

    def _exec_step(self, label, command, step_port=None):
        """Execute a nmap step, analyze output, return findings."""
        self.total_steps += 1
        step_n = self.total_steps

        step_banner(step_n, label)
        cmd = _ensure_sudo(command)
        print(f"\n  {DIM}${RESET} {cmd}\n")

        cmd_key = self._normalize_cmd(cmd)
        if cmd_key in self._executed:
            warn("Command already executed — skipping.")
            return self.planner.accumulated_findings[-1] if self.planner.accumulated_findings else {}
        self._executed.add(cmd_key)

        info("Executing via MCP...")
        result = self.mcp.run_nmap(cmd, self.target_ip, step_label=label)

        if result["success"]:
            success(f"Completed in {result['duration_s']}s")
        else:
            error(f"Error ({result['returncode']}): {result['stderr'][:100]}")

        if result["stdout"]:
            print()
            output_block(result["stdout"])

        # Snapshot services known BEFORE this step so interpret_findings can diff
        prior_services = {str(p): s for p, s in self._get_services().items()}
        insight = ""

        if self.dry_run:
            findings = {
                "open_ports": [], "filtered_ports": [], "services": {},
                "os_hint": "unknown", "firewall": {},
                "interesting_findings": ["[DRY-RUN]"], "suggested_followups": [],
                "nmap_cves": [], "step_label": label,
            }
        else:
            info("Analyzing results with LLM...")
            findings = self.planner.analyze_output(result["stdout"] + result["stderr"], label, step_port=step_port)

        if findings.get("open_ports"):
            ports_str = ", ".join(str(p) for p in findings["open_ports"])
            print(f"\n  {GREEN}✓{RESET}  Open: {ports_str}")
        for f in findings.get("interesting_findings", []):
            print(f"  {YELLOW}→{RESET}  {f}")

        # LLM interpretation — what do these results add to the picture?
        if not self.dry_run and result["stdout"]:
            info("Interpreting results...")
            insight = self.planner.interpret_findings(label, findings, prior_services)
            if insight:
                print(f"\n  {CYAN}{'─' * 52}{RESET}")
                print(f"  {BOLD}{CYAN}Insight{RESET}")
                # Wrap and indent each sentence
                for line in insight.strip().splitlines():
                    line = line.strip()
                    if line:
                        print(f"  {line}")
                print(f"  {CYAN}{'─' * 52}{RESET}")

        self.session_log.append({
            "step": step_n, "label": label, "tool": "nmap",
            "command": result["command_run"], "success": result["success"],
            "findings": findings, "output_preview": result["stdout"][:2000],
            "insight": insight if not self.dry_run and result["stdout"] else "",
        })
        return findings

    # ── Searchsploit early fingerprint ───────────────────────────

    def _run_searchsploit_early(self):
        """
        Query the local exploit-db mirror for every detected service version
        immediately after Phase 1, before the adaptive NSE planner runs.

        Queries are built from service *categories* (smb, ftp, ssh, …) rather
        than verbatim nmap service strings.  The raw nmap string "Windows XP
        microsoft-ds" returns 0 exploitdb hits; the category "smb" returns 72
        including EternalBlue (tagged "Windows 7/2008 R2") and MS08-067 —
        exactly the evidence the LLM needs to choose the correct module variant.

        For services with a concrete version (vsftpd 2.3.4, Apache 2.4.49, …)
        both the category AND the product+version are queried so precision hits
        are not lost.  An OS-level query is added for Windows/Linux targets to
        catch OS-indexed exploits (MS08-067, etc.).
        """
        if not check_tool("searchsploit"):
            return

        services     = self._get_services()
        consolidated = self.planner._consolidated_findings()
        os_hint      = consolidated.get("os_hint", "")

        # Collect queries, deduplicating by the query string itself.
        queries: dict[str, str] = {}   # label → search term
        seen_strings: set[str]  = set()

        for port, svc in sorted(services.items()):
            svc_clean = (svc or "").strip()
            if not svc_clean or svc_clean.lower() in ("unknown", "tcpwrapped"):
                continue

            port_int = int(port) if str(port).isdigit() else 0

            # Primary query: service category (smb, ftp, ssh, http, distcc …)
            cat = _detect_service_category(svc_clean, port_int)
            if cat and cat not in ("general",):
                if cat not in seen_strings:
                    seen_strings.add(cat)
                    queries[str(port)] = cat

            # Secondary query: product + version when nmap identified a version.
            # This catches specific version exploits (vsftpd 2.3.4, Apache 2.4.49)
            # that a generic category query would miss.
            product, version = _parse_service_string_generic(svc_clean)
            if version and product and product.lower() not in ("", "unknown", "microsoft"):
                pv = f"{product} {version}"
                if pv not in seen_strings:
                    seen_strings.add(pv)
                    queries[f"{port}_ver"] = pv

        # OS-level query — catches exploits indexed by OS+service (e.g. "windows
        # smb" surfaces MS08-067 and EternalBlue with their OS-version tags in the
        # title, while a plain "microsoft windows xp" query returns 2000+ noise
        # entries whose top-5 are unrelated).
        # Strategy: combine OS family word with the primary service category for a
        # tight, targeted query.  Falls back to the parsed product name when no
        # category-based queries exist (pure version-string targets like vsftpd).
        if os_hint and os_hint.lower() not in ("", "unknown"):
            os_lower = os_hint.lower()
            _OS_FAMILIES = ("windows", "linux", "ubuntu", "debian",
                            "centos", "fedora", "freebsd", "android")
            os_family_word = next(
                (w for w in _OS_FAMILIES if w in os_lower), None
            )
            primary_cat = next(iter(queries.values()), "") if queries else ""
            if os_family_word:
                # "windows smb", "linux ftp", "linux ssh" — concise and precise
                os_query = f"{os_family_word} {primary_cat}" if primary_cat else os_family_word
            else:
                product_os, _ = _parse_service_string_generic(os_hint)
                os_query = (product_os
                            if product_os and len(product_os.split()) > 1
                            else os_hint.split()[:2])
                if isinstance(os_query, list):
                    os_query = " ".join(os_query)
            if os_query and os_query not in seen_strings:
                seen_strings.add(os_query)
                queries["os"] = os_query

        if not queries:
            return

        header("SEARCHSPLOIT — Service fingerprint lookup")
        found_any = False
        for label, query in queries.items():
            try:
                proc = subprocess.run(
                    ["searchsploit", "--json", query],
                    capture_output=True, text=True, timeout=20,
                )
                entries = json.loads(proc.stdout).get("RESULTS_EXPLOIT", [])[:8]
            except Exception:
                entries = []
            if entries:
                self.searchsploit_results[label] = entries
                found_any = True
                info(f"[{label}] {query[:45]}: {len(entries)} match(es)")
                for e in entries[:3]:
                    title = (e.get("Title", "") or "")[:72]
                    print(f"  {DIM}  EDB-{e.get('EDB-ID','?')}: {title}{RESET}")
        if not found_any:
            info("No local exploit-db matches for detected services.")

    # ── Phase 2: LLM-planned adaptive scanning ───────────────────

    def _run_adaptive_phase(self):
        """
        The LLM plans what to scan (structured JSON) informed by RAG-retrieved
        script documentation. The orchestrator validates and builds commands.
        """
        rag_status = "RAG-informed" if self.planner.rag_available else "static catalog"
        header(f"PHASE 2 — Adaptive NSE scanning ({rag_status})")

        for ronda in range(1, MAX_ROUNDS + 1):
            if self.total_steps >= MAX_STEPS_TOTAL:
                warn(f"Step limit ({MAX_STEPS_TOTAL}) reached.")
                break

            if ronda > 1:
                header(f"ROUND {ronda} — Adaptive re-planning")

            info("LLM is analyzing findings and planning next steps...")
            plan = self.planner.create_plan(
                self.target_ip, self.objetivo,
                syn_confirmed=self._syn_confirmed_open,
                searchsploit_hits=self.searchsploit_results,
            )

            if plan.get("analysis"):
                info(f"Planner: {plan['analysis']}")

            if plan.get("pentest_complete"):
                success("LLM indicates all services are enumerated.")
                break

            steps = plan.get("steps", [])
            if not steps:
                info("LLM generated no more steps.")
                break

            for step in steps:
                if self.total_steps >= MAX_STEPS_TOTAL:
                    break

                label = step.get("label", f"Step {self.total_steps + 1}")
                scan_type = step.get("scan_type", "nse_scripts")
                port = step.get("port")
                scripts = step.get("scripts", [])
                reason = step.get("reason", "")

                if reason:
                    info(f"Reason: {reason}")

                # Build command from structured step (NEVER from LLM raw text)
                nmap_cmd = build_nmap_command(step, self.target_ip)

                # Execute
                findings = self._exec_step(label, nmap_cmd, step_port=port)

                # Track which scripts were run on which port
                if port and scripts:
                    self.planner.register_scripts_run(port, scripts)

                time.sleep(0.5)

    # ── HTTP port collection for ffuf ─────────────────────────────

    def _collect_http_ports(self):
        confirmed, candidates = set(), set()
        open_ports = set(self._get_open_ports())
        filtered = self._get_filtered()
        services = self._get_services()
        nse_meta = self._get_nse_meta()

        for p in open_ports:
            if p in filtered:
                continue
            svc = services.get(p, "").lower()

            # 1. NSE proved it speaks HTTP (http-title or http-server-header fired)
            if nse_meta.get(p, {}).get("is_http"):
                confirmed.add(p)
            # 2. Well-known HTTP port
            elif p in HTTP_WELL_KNOWN:
                confirmed.add(p)
            # 3. Service string contains HTTP keywords
            elif any(kw in svc for kw in HTTP_KEYWORDS):
                confirmed.add(p)
            # 4. Unknown service — candidate for probing
            elif svc in ("unknown", "", "tcpwrapped"):
                candidates.add(p)

        # Probe unknowns to confirm HTTP
        remaining = candidates - confirmed
        if remaining:
            confirmed.update(self._probe_http_ports(remaining))

        confirmed -= filtered
        result = sorted(confirmed)
        info(f"HTTP ports for ffuf: {result} (filtered: {sorted(filtered)})")
        return result

    def _probe_http_ports(self, ports):
        if not ports: return set()
        ps = ",".join(str(p) for p in sorted(ports))
        info(f"Probing {ps} for HTTP...")
        r = self.mcp.run_nmap(
            f"nmap -sV --script http-title -p {ps} --open {self.target_ip} --script-timeout 10s",
            self.target_ip, step_label="HTTP probe")
        found = set()
        if r["success"] and r["stdout"]:
            out = r["stdout"].lower()
            for port in ports:
                lines = [l for l in out.split("\n") if f"{port}/tcp" in l]
                if any(w in l for l in lines for w in ("http", "ssl", "title:", "web")):
                    found.add(port)
        return found

    def _get_hostname(self):
        for entry in self.session_log:
            text = entry.get("output_preview", "")
            for pat in [r"Nmap scan report for ([^\s(]+)\s+\(",
                        r"Location:\s*https?://([a-zA-Z][^\s/:]+)"]:
                m = re.search(pat, text)
                if m and not re.match(r"^\d+\.\d+\.\d+\.\d+$", m.group(1)):
                    return m.group(1)
        return ""

    # ── ffuf phase ────────────────────────────────────────────────

    def _run_ffuf_phase(self):
        if not check_tool("ffuf"):
            warn("ffuf not installed — skipped."); return
        http_ports = self._collect_http_ports()
        if not http_ports:
            info("No HTTP ports — ffuf skipped."); return

        header(f"PHASE 5 — FFUF fuzzing on {len(http_ports)} port(s)")
        hostname = self._get_hostname()
        if hostname: info(f"Hostname: {hostname}")

        for port in http_ports:
            proto = "https" if port == 443 else "http"
            ip_url = (f"{proto}://{self.target_ip}" if port in (80, 443)
                      else f"{proto}://{self.target_ip}:{port}")
            host_url = None
            if hostname and hostname != self.target_ip:
                host_url = (f"{proto}://{hostname}" if port in (80, 443)
                            else f"{proto}://{hostname}:{port}")

            print(f"\n  {BOLD}{CYAN}Port {port}{RESET}")
            ip_hits = self._ffuf_step(f"ffuf — {ip_url}", "files", ip_url, True)
            host_hits = []
            if host_url:
                host_hits = self._ffuf_step(f"ffuf — {host_url}", "files", host_url, True)

            # Recurse into directories
            all_hits = (ip_hits or []) + (host_hits or [])
            seen = set()
            for r in all_hits:
                if r.get("status") in (301, 302):
                    path = re.sub(r"https?://[^/]+", "", r.get("url", "")).rstrip("/")
                    if path and path not in seen:
                        seen.add(path)
                        self._ffuf_step(f"ffuf — {(host_url or ip_url)}{path}/", "files",
                                        f"{(host_url or ip_url)}{path}")
                        if len(seen) >= 3: break

            # Vhost
            self._vhost_scan(port, hostname, ip_url, host_url)

        # #3 / #7 — context-aware follow-up scans (e.g. /cgi-bin/ for Apache)
        self._context_aware_ffuf_steps(http_ports)

    def _vhost_scan(self, port, hostname, ip_url, host_url):
        vb = hostname or self.target_ip
        vt = host_url or ip_url
        wl = find_vhost_wordlist() or find_wordlist()
        if not wl: return
        cmd = (f"ffuf -u {vt} -w {wl} -t 40 -H 'Host: FUZZ.{vb}'"
               f" -o /tmp/ffuf_vhost_{port}_{int(time.time())}.json -of json -v -ac")
        self.total_steps += 1
        step_banner(self.total_steps, f"ffuf vhosts — FUZZ.{vb}")
        result = self.ffuf.run_ffuf(cmd, vt, step_label=f"ffuf vhosts — FUZZ.{vb}",
                                    target_ip=self.target_ip, domain=vb)
        print(f"\n  {BOLD}Command:{RESET} {YELLOW}{result['command_run']}{RESET}\n")
        hits = result.get("results", [])
        if result["success"]: success(f"{result['duration_s']}s — {len(hits)} vhosts")
        else: error(result['stderr'][:120])

        # Transform vhost hits: replace generic url with actual FQDN
        # ffuf stores the base url in "url" but the vhost name is in input.FUZZ
        vhost_hits = []
        for r in (hits or []):
            if not isinstance(r, dict):
                continue
            fv = r.get("input", {}).get("FUZZ", "?")
            fqdn = f"{fv}.{vb}"
            c = GREEN if r["status"]==200 else YELLOW if r["status"] in (301,302,403) else DIM
            print(f"  {c}[{r['status']}]{RESET}  {fqdn}  {DIM}({r.get('length',0)} bytes){RESET}")
            # Create a copy with the correct URL for logging/PDF
            vhost_hits.append({
                "url": fqdn,
                "status": r["status"],
                "length": r.get("length", 0),
            })

        if vhost_hits:
            print(f"\n  {YELLOW}Add to /etc/hosts:{RESET}")
            for vh in vhost_hits:
                print(f"  {YELLOW}   echo '{self.target_ip} {vh['url']}' >> /etc/hosts{RESET}")

        self._log_ffuf(f"ffuf vhosts — FUZZ.{vb}", result, vhost_hits, vb)

    def _context_aware_ffuf_steps(self, http_ports: list[int]):
        """
        Run service-conditioned follow-up web discovery.

        Apache detected  → fuzz /cgi-bin/ with a CGI-specific wordlist so
                           TARGETURI is resolvable for apache_mod_cgi_bash_env_exec.
        IIS / WebDAV     → HTTP OPTIONS probe per discovered path; writable verbs
                           surface "webdav_writable" evidence for the NSE extractor.
        """
        consolidated = self.planner._consolidated_findings()
        services     = consolidated.get("services", {})
        findings_raw = " ".join(str(f) for f in consolidated.get("interesting_findings", []))

        # CGI wordlist: prefer seclists CGIs.txt → quickhits → common (ascending specificity)
        cgi_wl = next(
            (p for p in (
                "/usr/share/seclists/Discovery/Web-Content/LEGACY-SERVICES/CGIs/CGIs.txt",
                "/usr/share/seclists/Discovery/Web-Content/quickhits.txt",
                "/usr/share/dirb/wordlists/common.txt",
            ) if os.path.exists(p)),
            None,
        )

        for port in http_ports:
            svc  = services.get(str(port), "").lower()
            proto = "https" if port == 443 else "http"
            base  = (f"{proto}://{self.target_ip}" if port in (80, 443)
                     else f"{proto}://{self.target_ip}:{port}")

            # ── Apache: CGI script discovery ─────────────────────────────────
            if "apache" in svc and cgi_wl:
                cgi_url = f"{base}/cgi-bin"
                label   = f"ffuf CGI — {cgi_url}"
                cmd = (
                    f"ffuf -u {cgi_url}/FUZZ -w {cgi_wl} -t 40 -v -timeout 10 "
                    f"-e .sh,.cgi,.pl,.py,.rb "
                    f"-o /tmp/ffuf_cgi_{port}_{int(time.time())}.json -of json -mc all -ac"
                )
                key = re.sub(r"\s+", " ", re.sub(r"-o\s+\S+", "", cmd)).strip()
                if key not in self._executed_ffuf:
                    self._executed_ffuf.add(key)
                    self.total_steps += 1
                    step_banner(self.total_steps, label)
                    result = self.ffuf.run_ffuf(cmd, cgi_url, step_label=label)
                    print(f"\n  {BOLD}Command:{RESET} {YELLOW}{result['command_run']}{RESET}\n")
                    hits = result.get("results", [])
                    if result["success"]:
                        success(f"{result['duration_s']}s — {len(hits)} CGI path(s) found")
                    for r in (hits or [])[:20]:
                        c = GREEN if r["status"] == 200 else YELLOW if r["status"] in (301, 302, 403) else DIM
                        print(f"  {c}[{r['status']}]{RESET}  {r['url']}  {DIM}({r.get('length', 0)} bytes){RESET}")
                    self._log_ffuf(label, result, hits, cgi_url)

            # ── IIS / WebDAV: OPTIONS probe to surface writable verbs ─────────
            # Only probe when IIS is detected OR WebDAV terms already appear in
            # findings (http-webdav-scan output may not include PUT explicitly).
            is_iis    = "iis" in svc or "microsoft-iis" in svc
            has_webdav = re.search(r"webdav|propfind", findings_raw, re.I)
            if (is_iis or has_webdav) and check_tool("curl"):
                label = f"WebDAV OPTIONS probe — {base}"
                key   = f"webdav_options_{port}"
                if key not in self._executed_ffuf:
                    self._executed_ffuf.add(key)
                    self.total_steps += 1
                    step_banner(self.total_steps, label)
                    try:
                        proc = subprocess.run(
                            ["curl", "-s", "-X", "OPTIONS", base,
                             "-D", "-", "--max-time", "10"],
                            capture_output=True, text=True, timeout=15,
                        )
                        allow_hdr = ""
                        for line in proc.stdout.splitlines():
                            if line.lower().startswith("allow:") or line.lower().startswith("ms-author-via:"):
                                allow_hdr += line + " "
                                print(f"  {CYAN}→{RESET}  {line.strip()}")
                        # Record result as an interesting finding so NSE extractor picks it up
                        if allow_hdr:
                            finding = f"WebDAV OPTIONS on port {port}: {allow_hdr.strip()}"
                            self.planner.accumulated_findings.append({
                                "interesting_findings": [finding],
                                "open_ports": [],
                                "services": {},
                                "os_hint": "",
                                "firewall": {},
                                "nmap_cves": [],
                                "suggested_followups": [],
                            })
                            info(f"WebDAV methods recorded → {allow_hdr.strip()[:80]}")
                    except Exception as e:
                        warn(f"WebDAV OPTIONS probe failed: {e}")

    def _ffuf_step(self, label, scan_type, target_url, return_hits=False):
        self.total_steps += 1
        step_banner(self.total_steps, label)
        cmd = build_ffuf_command(scan_type, target_url=target_url)
        key = re.sub(r"-o\s+\S+", "", cmd)
        key = re.sub(r"\s+", " ", key).strip()
        if key in self._executed_ffuf:
            warn("Already executed — skipping.")
            return [] if return_hits else None
        self._executed_ffuf.add(key)
        info("Executing via MCP (ffuf)...")
        result = self.ffuf.run_ffuf(cmd, target_url, step_label=label)
        print(f"\n  {BOLD}Command:{RESET} {YELLOW}{result['command_run']}{RESET}\n")
        hits = result.get("results", [])
        if result["success"]: success(f"{result['duration_s']}s — {len(hits)} paths")
        else: error(result['stderr'][:120])
        for r in (hits or [])[:30]:
            c = GREEN if r["status"]==200 else YELLOW if r["status"] in (301,302,403) else DIM
            print(f"  {c}[{r['status']}]{RESET}  {r['url']}  {DIM}({r['length']} bytes){RESET}")
        self._log_ffuf(label, result, hits, target_url)
        return hits if return_hits else None

    def _log_ffuf(self, label, result, hits, base_url):
        interesting = [f"[{r['status']}] {r.get('url', r.get('input',{}).get('FUZZ','?'))}"
                       for r in hits if isinstance(r,dict) and r.get("status") in (200,301,302,403)]
        findings = {
            "open_ports": [], "services": {}, "os_hint": "unknown",
            "interesting_findings": interesting[:15],
            "suggested_followups": [r.get("url","") for r in hits
                                    if isinstance(r,dict) and r.get("status")==200 and r.get("length",0)>200][:5],
            "step_label": label,
            "ffuf_results": [{"url": r.get("url",""), "status": r["status"], "size": r.get("length",0)}
                             for r in hits if isinstance(r, dict)],
        }
        self.planner.accumulated_findings.append(findings)
        self.session_log.append({
            "step": self.total_steps, "label": label, "tool": "ffuf",
            "command": result["command_run"], "success": result["success"],
            "findings": findings, "output_preview": "\n".join(interesting[:10]),
        })

    # ── MSF exploitation phase ────────────────────────────────────

    def _build_scan_results(self, det_recs: list[dict] | None = None) -> dict:
        """Convert nmap findings to the format MSF orchestrator expects.
        Merges NVD CVEs with deterministic recommendations so MSF sees both."""
        import socket

        consolidated = self.planner._consolidated_findings()
        os_raw = consolidated.get("os_hint", "")
        os_lower = os_raw.lower()

        if "windows" in os_lower:
            os_family = "windows"
        elif any(x in os_lower for x in ("linux", "ubuntu", "debian", "centos", "fedora")):
            os_family = "linux"
        elif any(x in os_lower for x in ("mac", "darwin", "osx")):
            os_family = "macos"
        else:
            os_family = "unknown"

        # Use architecture from nmap -O XML if available (most accurate).
        # Fall back to inference from os_hint string.
        if self._detected_arch:
            arch = self._detected_arch
        else:
            arch = "x86_64"
            if any(x in os_lower for x in ("i386", "i686", "32-bit",
                                            "windows xp", "windows server 2003",
                                            "windows 2000", "windows nt")):
                arch = "x86"
            elif "arm" in os_lower:
                arch = "arm"

        # Convert services to MSF format
        services = []
        for port in consolidated["open_ports"]:
            svc_str = consolidated["services"].get(str(port), "unknown")
            parts = svc_str.split()
            service_name = parts[0].lower() if parts else "unknown"
            version = " ".join(parts[1:]) if len(parts) > 1 else ""
            services.append({"port": port, "service": service_name, "version": svc_str})

        # Infer Windows from well-known Windows-exclusive service names when
        # OS detection produced nothing (common on XP/2003 over VPN).
        if os_family == "unknown":
            _WIN_SVCS = {"microsoft-ds", "msrpc", "netbios-ssn", "netbios-ns", "ms-wbt-server"}
            svc_names = {s["service"].lower() for s in services}
            has_samba = any("samba" in s["version"].lower() for s in services)
            if not has_samba and svc_names & _WIN_SVCS:
                os_family = "windows"

        # Convert NVD CVEs to MSF format
        cves = []
        seen_cve_ids = set()
        for svc_entry in self.nvd_data:
            try:
                port = int(svc_entry.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            service = svc_entry.get("service", "")
            for cve in svc_entry.get("cves") or []:
                try:
                    cvss = float(cve.get("score") or 0.0)
                except (TypeError, ValueError):
                    cvss = 0.0
                cve_id = cve.get("cve_id", "")
                if cve_id:
                    seen_cve_ids.add(cve_id)
                cves.append({
                    "id":      cve_id,
                    "cvss":    cvss,
                    "service": service,
                    "port":    port,
                })

        # Collect all interesting_findings for CGI path lookup (used by Shellshock below)
        consolidated = self.planner._consolidated_findings()
        all_findings = consolidated.get("interesting_findings", [])

        # Merge deterministic recommendations (known exploit vectors not in NVD).
        # Pass msf_module through so the planner takes the deterministic fast path
        # instead of spending time on RAG/LLM for modules we already know.
        if det_recs:
            for rec in det_recs:
                cve_id = rec.get("cve", "")
                if cve_id and cve_id not in seen_cve_ids:
                    seen_cve_ids.add(cve_id)
                    sev_to_cvss = {"CRITICAL": 9.8, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0}
                    msf_mod = rec.get("metasploit", "")
                    msf_options: dict = {}

                    # Hardcoded TARGETURI lookup disabled — module option resolution
                    # is now fully handled by _required_module_options() +
                    # _fill_options_from_context() in msf_planner.py.
                    # Re-enable the block below if the model cannot fill TARGETURI:
                    #
                    # if "apache_mod_cgi_bash_env_exec" in msf_mod:
                    #     cgi_port = str(rec.get("port", "80"))
                    #     cgi_path = "/cgi-bin/user.sh"  # Shocker default
                    #     for f_str in all_findings:
                    #         m = re.search(
                    #             r"CGI script found on port " + re.escape(cgi_port) + r":\s*(\S+)",
                    #             str(f_str), re.I,
                    #         )
                    #         if m:
                    #             cgi_path = m.group(1).strip()
                    #             break
                    #     msf_options["TARGETURI"] = cgi_path

                    cves.append({
                        "id":          cve_id,
                        "cvss":        sev_to_cvss.get(rec.get("severity", ""), 5.0),
                        "service":     rec.get("detected_service", ""),
                        "port":        int(rec.get("port", 0) or 0),
                        "msf_module":  msf_mod,
                        "msf_options": msf_options,
                    })

        # Detect LHOST — route toward the TARGET (not 8.8.8.8) so that the
        # correct VPN interface (tun0) is chosen when running against HTB machines.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.target_ip, 80))
            lhost = s.getsockname()[0]
            s.close()
        except Exception:
            lhost = "127.0.0.1"

        # Attach pre-built evidence candidates (populated by _build_evidence_candidates
        # before the MSF phase).  Stored as extra entries in cves so generate_plan
        # picks them up without any structural change to its iteration loop.
        extra = getattr(self, "_extra_cve_entries", [])
        if extra:
            existing_ids = {c.get("id", "").upper() for c in cves if c.get("id")}
            for e in extra:
                if e.get("id", "").upper() not in existing_ids:
                    cves.append(e)

        return {
            "target": self.target_ip, "os": os_raw, "os_family": os_family,
            "arch": arch, "services": services, "cves": cves, "lhost": lhost,
        }

    def _build_evidence_candidates(self):
        """
        Build enriched CVE entries from all evidence sources (KEV, NSE signals,
        searchsploit) and store them on self._extra_cve_entries.

        Called once before the MSF phase, after NVD + NSE CVE merging.
        _build_scan_results() attaches these extras to scan_results["cves"]
        so msf_planner.generate_plan iterates them without structural changes.
        """
        if not EVIDENCE_AGGREGATOR_AVAILABLE:
            self._extra_cve_entries = []
            return
        try:
            header("EVIDENCE CANDIDATE INDEX")
            kev = KevClient()
            base = self._build_scan_results(det_recs=[])
            findings = self.planner._consolidated_findings().get(
                "interesting_findings", []
            )
            self._extra_cve_entries = build_extra_cve_entries(
                scan_results         = base,
                searchsploit_results = self.searchsploit_results,
                interesting_findings = findings,
                kev_client           = kev,
            )
        except Exception as e:
            warn(f"Evidence candidate build error: {e}")
            import traceback; traceback.print_exc()
            self._extra_cve_entries = []

    def _ensure_cgi_paths(self, scan_results: dict):
        """
        #7 — If Apache is in the scan and no CGI paths have been found yet,
        run a targeted /cgi-bin/ scan so TARGETURI can be resolved before MSF fires.
        This is the safety net for cases where the ffuf phase ran before the service
        was fully identified, or the Apache CGI scan was skipped for another reason.
        """
        has_apache = any(
            "apache" in svc.get("version", "").lower()
            for svc in scan_results.get("services", [])
        )
        if not has_apache:
            return

        all_findings = self.planner._consolidated_findings().get("interesting_findings", [])
        cgi_found = any("cgi" in str(f).lower() for f in all_findings)
        if cgi_found:
            return  # already have CGI discovery data

        http_ports = [
            svc["port"] for svc in scan_results.get("services", [])
            if svc.get("service", "").lower() in ("http", "https")
               or svc.get("port") in (80, 443, 8080, 8443)
        ]
        if http_ports:
            info("Apache without CGI paths — running targeted /cgi-bin/ scan...")
            self._context_aware_ffuf_steps(http_ports)

    def _run_msf_phase(self, det_recs: list[dict] | None = None):
        """Run Metasploit exploitation phase if CVEs were found and user confirms."""
        if not MSF_AVAILABLE:
            info("MSF modules not available — exploitation phase skipped.")
            return
        if self.dry_run:
            info("Dry-run mode — MSF phase skipped.")
            return

        # Count CVEs from NVD + deterministic recs + evidence-aggregator extras
        nvd_cve_count  = sum(len(s.get("cves", [])) for s in self.nvd_data) if self.nvd_data else 0
        det_cve_count  = len(det_recs) if det_recs else 0
        extra_count    = len(getattr(self, "_extra_cve_entries", []))
        total_cves     = nvd_cve_count + det_cve_count
        total_candidates = total_cves + extra_count

        if total_candidates == 0:
            info("No exploit candidates — MSF phase skipped.")
            return

        header(
            f"PHASE 6 — Metasploit exploitation "
            f"({total_cves} CVE(s): {nvd_cve_count} NVD + {det_cve_count} det"
            f"{f' + {extra_count} KEV/NSE/ssp' if extra_count else ''})"
        )

        try:
            scan_results = self._build_scan_results(det_recs=det_recs)

            # #7 — if Apache is present and we haven't yet found CGI paths, run a
            # targeted /cgi-bin/ scan now so _fill_options_from_context can set
            # TARGETURI correctly for apache_mod_cgi_bash_env_exec.
            self._ensure_cgi_paths(scan_results)
            # Rebuild after potential new CGI discoveries
            scan_results = self._build_scan_results(det_recs=det_recs)

            info(f"Building MSF RAG index for {scan_results['os_family']}/{scan_results['arch']}...")
            msf_index = msf_build_index(scan_results)

            msf_orch = MsfOrchestrator(scan_results, msf_index, dry_run=True)
            msf_findings = msf_orch.run()

            self._msf_orch   = msf_orch
            self.msf_findings = msf_findings   # passed to unified PDF

            self.session_log.append({
                "step": self.total_steps + 1, "label": "MSF exploitation phase",
                "tool": "msf", "command": "msfconsole (multiple modules)",
                "success": not msf_findings.get("interrupted", False),
                "findings": {"msf_results": msf_findings},
                "output_preview": f"{len(msf_findings.get('results', []))} modules executed",
            })

        except Exception as e:
            error(f"MSF phase error: {e}")
            import traceback
            traceback.print_exc()

    def _run_exploit_runner_phase(self, det_recs: list[dict] | None = None):
        """Phase 7 — searchsploit exploit scripts + default credential checks."""
        if not EXPLOIT_RUNNER_AVAILABLE:
            info("exploit_runner not available — Phase 7 skipped.")
            return
        if self.dry_run:
            info("Dry-run mode — Phase 7 skipped.")
            return
        try:
            scan_results = self._build_scan_results(det_recs=det_recs)
            findings = exploit_runner_run(scan_results)
            self.exploit_runner_findings = findings
            self.session_log.append({
                "step":    self.total_steps + 1,
                "label":   "Searchsploit + credential phase",
                "tool":    "exploit_runner",
                "command": "searchsploit / paramiko / ftplib",
                "success": bool(findings.get("sessions") or findings.get("creds_found")),
                "findings": {"exploit_runner": findings},
                "output_preview": (
                    f"{len(findings.get('exploits_tried', []))} exploits tried, "
                    f"{len(findings.get('sessions', []))} shells, "
                    f"{len(findings.get('creds_found', []))} creds"
                ),
            })
        except Exception as e:
            error(f"Phase 7 error: {e}")
            import traceback
            traceback.print_exc()

    def _record_phase(self, name: str, t0: datetime):
        dur = (datetime.now() - t0).total_seconds()
        self.phase_timings.append({"name": name, "duration_s": dur})
        print(f"  {DIM}⏱  {name}: {dur:.1f}s{RESET}")

    # ── Main loop ─────────────────────────────────────────────────

    def run(self):
        self.start_time = datetime.now()
        header(f"ADAPTIVE PENTEST — Target: {self.target_ip}")
        if self.dry_run: warn("DRY-RUN mode.")
        if self.objetivo: info(f"Objective: {self.objetivo}")
        print()

        self._init_rag()

        if not self.dry_run:
            _t = datetime.now()
            header("MODEL WARM-UP — Loading LLM weights")
            self.planner.warm_up()
            self._record_phase("Model warm-up", _t)

        try:
            _t = datetime.now()
            header("PHASE 0 — Full TCP port discovery")
            self._exec_step("Full TCP SYN scan (all 65535 ports)",
                            f"nmap -Pn -sS -p- --min-rate 1000 --max-retries 2 {self.target_ip}")
            # Capture the authoritative open-port set before any other scan type
            # can introduce noise.  This set is passed to the adaptive planner so
            # it can distinguish a SYN-confirmed open port from a later filtered
            # result caused by timing or rate-limiting on the remote host.
            self._syn_confirmed_open = set(self._get_open_ports())
            self._record_phase("Phase 0 — TCP Discovery", _t)

            time.sleep(10)

            _t = datetime.now()
            header("PHASE 1 — Version detection")
            ps = self._ports_str(default="1-1000")
            xml_path = os.path.join(os.getcwd(), "outputs", f"nmap_sV_{self.target_ip.replace('.', '_')}.xml")
            os.makedirs(os.path.join(os.getcwd(), "outputs"), exist_ok=True)

            self._exec_step(
                f"Version + OS detection on {ps if ps != '1-1000' else 'top-1000 ports (Phase 0 fallback)'}",
                f"nmap -Pn -sV -O --version-intensity 5 -sC --script-timeout 60s"
                f" -p {ps} -oX {xml_path} {self.target_ip}",
            )
            self._nmap_xml_path = xml_path
            self._record_phase("Phase 1 — Version Detection", _t)

            # Query searchsploit for detected services immediately after version
            # detection — before the adaptive NSE phase — so the LLM planner has
            # exploit-DB evidence when deciding which vulnerability scripts to run.
            self._run_searchsploit_early()

            _t = datetime.now()
            self._run_adaptive_phase()
            self._record_phase("Phase 2 — Adaptive NSE", _t)

            # ACK firewall-detection runs after NSE so its port-state judgements
            # (filtered = stateful firewall drops ACK) cannot poison nmap's internal
            # state cache before the vulnerability scripts execute.
            _ack_ports = self._ports_str(
                default="21,22,23,25,80,110,135,139,143,443,445,3306,3389,3632,8080,8443"
            )
            _t = datetime.now()
            header("PHASE 3 — Firewall detection")
            self._exec_step("ACK scan — firewall detection",
                            f"nmap -Pn -sA -p {_ack_ports} {self.target_ip}")
            self._record_phase("Phase 3 — Firewall Detection", _t)

            if self.total_steps < MAX_STEPS_TOTAL:
                _t = datetime.now()
                header("PHASE 4 — UDP scan")
                self._exec_step(
                    "UDP scan — top 100 ports by frequency",
                    f"nmap -Pn -sU --top-ports 100 --open --max-retries 1 {self.target_ip}",
                )
                # Second pass: ports that are rare in general internet traffic but
                # host services with known exploit modules or critical misconfigurations.
                # These are often missed by frequency-ranked scans.
                _UDP_EXPLOIT_PORTS = (
                    "53,67,69,111,123,137,138,161,162,"  # DNS,DHCP,TFTP,RPC,NTP,NetBIOS,SNMP
                    "500,623,1434,1900,4500,5353,"        # IKE,IPMI,MSSQL,UPnP,NAT-T,mDNS
                    "11211,17185"                          # Memcached,VxWorks debug
                )
                self._exec_step(
                    "UDP scan — exploit-focused service ports",
                    f"nmap -Pn -sU -p {_UDP_EXPLOIT_PORTS} --open --max-retries 1 {self.target_ip}",
                )
                self._record_phase("Phase 4 — UDP Scan", _t)

        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}⚠  Interrupted — generating partial reports...{RESET}\n")
        except Exception as e:
            print(f"\n{RED}Error: {e}{RESET}")
            import traceback; traceback.print_exc()
        finally:
            _t = datetime.now()
            try: self._run_ffuf_phase()
            except Exception as e:
                print(f"\n{RED}ffuf error: {e}{RESET}")
                import traceback; traceback.print_exc()
            self._record_phase("Phase 5 — Web Fuzzing", _t)

            if self.total_steps > 0:
                self._final_report()

    # ── Final report ──────────────────────────────────────────────

    def _final_report(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        bar = "─" * W
        print(f"\n{BOLD}{CYAN}{bar}{RESET}")
        print(f"{BOLD}{CYAN}  SCAN SUMMARY{RESET}")
        print(f"{BOLD}{CYAN}{bar}{RESET}")
        # Meta block — two-column label/value
        meta = [
            ("Target",   self.target_ip),
            ("Steps",    str(self.total_steps)),
            ("Duration", f"{elapsed:.0f} s  ({elapsed / 60:.1f} min)"),
            ("Started",  self.start_time.strftime("%Y-%m-%d  %H:%M:%S")),
        ]
        for label, value in meta:
            print(f"  {DIM}{label:<10}{RESET}  {BOLD}{value}{RESET}")
        print(f"  {DIM}{bar}{RESET}\n")
        print(self.mcp.get_history_summary())
        print()

        info("Generating executive analysis (LLM)...")
        report_text = self.planner.final_report(self.target_ip)
        print(f"\n{_render_markdown(report_text)}\n")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if not self.dry_run:
            header("QUERYING NVD (NIST)")
            try:
                # NEW: Parse nmap XML for structured product/version data
                nmap_xml_services = self._parse_nmap_xml()

                self.nvd_data = enrich_with_nvd(
                    self.planner.accumulated_findings, api_key=self.nvd_api_key,
                    target_ip=self.target_ip, session_log=self.session_log,
                    nmap_xml_services=nmap_xml_services)

                # Merge CVEs found by NSE scripts (e.g. smb-vuln-ms17-010 → CVE-2017-0143)
                # that were missed by the NVD keyword search.
                self.nvd_data = merge_nse_cves(
                    self.nvd_data, self.planner.accumulated_findings,
                    api_key=self.nvd_api_key)

                total = sum(len(s.get("cves", [])) for s in self.nvd_data)
                success(f"{total} CVEs found.")
                for svc in self.nvd_data:
                    for cve in svc.get("cves", []):
                        sev = cve.get("severity", "")
                        if sev in ("CRITICAL", "HIGH"):
                            c = RED if sev == "CRITICAL" else YELLOW
                            print(f"  {c}[{sev}]{RESET}  {cve['cve_id']}  ·  {cve.get('score','?')}  ·  {svc['service']}")
            except Exception as e:
                warn(f"NVD error: {e}"); self.nvd_data = []

        # ── Deterministic recommendations ────────────────────────────────────
        det_recs: list[dict] = []
        try:
            det_recs = self.planner.generate_deterministic_recommendations()
            if det_recs:
                info(f"Deterministic recommendations: {len(det_recs)} confirmed exploit vectors")
                for r in det_recs:
                    c = RED if r["severity"] == "CRITICAL" else YELLOW if r["severity"] == "HIGH" else DIM
                    print(f"  {c}[{r['severity']}]{RESET}  {r['cve']}  ·  {r['title']}")
        except Exception as e:
            warn(f"Deterministic recommendations error: {e}")

        # ── LLM exploit planning — structured JSON from gathered evidence ────
        # The LLM identifies WHICH vulnerabilities to exploit (CVE + service +
        # port); the MSF planner's RAG+LLM path selects the specific module by
        # reading module documentation, ensuring OS-version–compatible selection
        # (e.g. ms17_010_psexec for XP/2003 vs ms17_010_eternalblue for Vista+).
        if not self.dry_run:
            try:
                scan_ctx = self._build_scan_results(det_recs=[])
                llm_recs = self.planner.plan_exploitation(self.target_ip, {
                    **scan_ctx,
                    "searchsploit":   self.searchsploit_results,
                    "nvd_cves":       self.nvd_data,
                    "report_summary": report_text[:2000],
                })
                if llm_recs:
                    header("LLM EXPLOIT PLAN")
                    # Deduplicate by CVE+port — no module field in llm_recs
                    seen_cve_ports = {
                        (r.get("cve", ""), int(r.get("port", 0) or 0))
                        for r in det_recs
                    }
                    for rec in llm_recs:
                        c = RED if rec.get("severity") == "CRITICAL" else YELLOW
                        print(f"  {c}[{rec.get('severity','?')}]{RESET}  "
                              f"{rec.get('cve','?')}  ·  {rec.get('title','?')}")
                        key = (rec.get("cve", ""), int(rec.get("port", 0) or 0))
                        if key not in seen_cve_ports:
                            det_recs.append(rec)
                            seen_cve_ports.add(key)
            except Exception as e:
                warn(f"LLM exploit planning error: {e}")

        # ── Evidence candidate index (KEV + NSE signals + searchsploit) ────────
        # Must run after NVD + LLM planning so it can see all existing CVE-IDs
        # and avoid creating duplicates.  Populates self._extra_cve_entries which
        # _build_scan_results() then injects into scan_results["cves"].
        if not self.dry_run:
            self._build_evidence_candidates()

        # ── Phase 6: MSF exploitation (NVD CVEs + LLM + KEV/NSE candidates) ──
        _t6 = datetime.now()
        try:
            self._run_msf_phase(det_recs=det_recs)
        except Exception as e:
            warn(f"MSF phase error: {e}")
        self._record_phase("Phase 6 — Metasploit", _t6)

        # ── Phase 7: Searchsploit + default credentials ───────────────────────
        _t7 = datetime.now()
        try:
            self._run_exploit_runner_phase(det_recs=det_recs)
        except Exception as e:
            warn(f"Phase 7 error: {e}")
        self._record_phase("Phase 7 — Searchsploit + Creds", _t7)

        header("GENERATING PDF REPORT")
        total_elapsed = (datetime.now() - self.start_time).total_seconds()
        try:
            path_sum, _ = generate_reports(
                target_ip=self.target_ip, session_log=self.session_log,
                accumulated_findings=self.planner.accumulated_findings,
                final_report_text=report_text, nvd_data=self.nvd_data,
                timestamp=timestamp, det_recs=det_recs,
                phase_timings=self.phase_timings,
                total_elapsed=total_elapsed,
                msf_findings=self.msf_findings)
            print(f"\n  {GREEN}✓{RESET}  Report: {path_sum}\n")
        except Exception as e:
            error(f"PDF error: {e}"); import traceback; traceback.print_exc()

        os.makedirs("RESULT", exist_ok=True)
        log_path = os.path.join("RESULT", f"pentest_{self.target_ip.replace('.','_')}_{timestamp}.txt")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"PENTEST LOG — {self.target_ip}\nDate: {self.start_time.isoformat()}\n{'='*60}\n\n")
            for e in self.session_log:
                f.write(f"[Step {e['step']}] {e['label']}\n  Cmd: {e['command']}\n  OK: {e['success']}\n  Out:\n{e['output_preview']}\n{'-'*40}\n")
            f.write(f"\n{'='*60}\nEXECUTIVE REPORT:\n{report_text}\n")
        success(f"Log: {log_path}")

        # ── Push notification ─────────────────────────────────────────────
        _notify_done(self.target_ip, total_elapsed, self.total_steps, self.msf_findings)

        # ── Interactive session (LAST action — blocks until user exits) ───
        if self._msf_orch and self._msf_orch.has_successful_exploits():
            self._msf_orch.launch_interactive_session()


def main():
    parser = argparse.ArgumentParser(description="Adaptive pentest orchestrator")
    parser.add_argument("--target", type=str)
    parser.add_argument("--objetivo", type=str, default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--nvd-key", type=str, default="")
    args = parser.parse_args()
    sys.stdout.write("Target > "); sys.stdout.flush()
    target = args.target or sys.stdin.readline().rstrip("\r\n").strip()
    if not target: print("Error: target required."); sys.exit(1)
    objetivo = args.objetivo or ""
    nvd_key = args.nvd_key or os.getenv("NVD_KEY", "")
    bar = "─" * W
    print(f"\n{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}{CYAN}  PENTEST TOOLKIT  ·  nmap adaptive orchestrator{RESET}")
    print(f"{BOLD}{CYAN}{bar}{RESET}")
    print(f"  {DIM}Target{RESET}    {BOLD}{target}{RESET}")
    print(f"  {DIM}Objective{RESET} {objetivo or 'General recon'}")
    print(f"  {DIM}Dry-run{RESET}   {'YES' if args.dry_run else 'NO'}\n")
    NmapOrchestrator(target_ip=target, objetivo=objetivo, dry_run=args.dry_run, nvd_api_key=nvd_key).run()

if __name__ == "__main__":
    main()