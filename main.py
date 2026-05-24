"""
main.py — Selector de modo: Pentest nmap / Debsecan / Lynis

Uso:
    python3 main.py                          → menú interactivo
    python3 main.py --mode nmap   --target 10.129.7.3
    python3 main.py --mode debsecan
    python3 main.py --mode lynis
    python3 main.py --mode debsecan --only-fixed --nvd-key TU_KEY
    python3 main.py --mode lynis    --no-sudo   --nvd-key TU_KEY
    python3 main.py --mode nmap     --target 10.129.7.3 --dry-run
"""

import argparse
import sys
import os

# Re-enable CR→NL translation in case a previous process left the tty
# in raw/cbreak mode without restoring it (shows as ^M on Enter key).
try:
    import termios
    _fd = sys.stdin.fileno()
    _attrs = termios.tcgetattr(_fd)
    _attrs[0] |= termios.ICRNL   # input:  translate CR to NL
    _attrs[1] |= termios.ONLCR   # output: translate NL to CR+NL
    termios.tcsetattr(_fd, termios.TCSANOW, _attrs)
    del _fd, _attrs
except Exception:
    pass

def _input(prompt: str) -> str:
    """input() that works even when Enter sends \\r instead of \\n."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return sys.stdin.readline().rstrip("\r\n")

# ──────────────────────────────────────────────────────────────────────────────
# COLORES
# ──────────────────────────────────────────────────────────────────────────────

BOLD   = "\033[1m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗
║          SECURITY TOOLKIT — Powered by IA + RAG             ║
║                                                              ║
║   [1] Pentest de Red      (nmap adaptativo + NVD)            ║
║   [2] Scan Local Paquetes (debsecan + CVE report)            ║
║   [3] Auditoria Sistema   (lynis + NVD enrichment)           ║
║   [4] Consulta CVE        (NVD API + analisis LLM)           ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""


# ──────────────────────────────────────────────────────────────────────────────
# VERIFICACIÓN DE DEPENDENCIAS
# ──────────────────────────────────────────────────────────────────────────────

def check_tool(tool: str) -> bool:
    """Comprueba si una herramienta está instalada."""
    import subprocess
    r = subprocess.run(["which", tool], capture_output=True)
    return r.returncode == 0


def check_imports() -> dict:
    """Verifica que los módulos Python necesarios están disponibles."""
    missing = []
    for module in ["reportlab", "numpy", "huggingface_hub", "sentence_transformers"]:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    return missing


# ──────────────────────────────────────────────────────────────────────────────
# MODO NMAP
# ──────────────────────────────────────────────────────────────────────────────

def run_nmap_mode(args):
    print(f"\n{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  MODO: PENTEST DE RED (nmap adaptativo){RESET}")
    print(f"{CYAN}{'═'*60}{RESET}\n")

    if not check_tool("nmap"):
        print(f"{RED}[ERROR] nmap no está instalado. Ejecuta: sudo apt install nmap{RESET}")
        sys.exit(1)

    if not check_tool("ffuf"):
        print(f"{YELLOW}[WARN]  ffuf no está instalado — el fuzzing web no estará disponible.")
        print(f"   Instalar: sudo apt install ffuf{RESET}\n")

    try:
        from nmap_orchestrator import NmapOrchestrator
    except ImportError as e:
        print(f"{RED}[ERROR] Error importando orquestador: {e}{RESET}")
        sys.exit(1)

    target = args.target
    if not target:
        target = _input("Target IP or range > ").strip()
    if not target:
        print(f"{RED}[ERROR] Target requerido.{RESET}")
        sys.exit(1)

    objetivo = args.objetivo or ""
    if not objetivo:
        objetivo = _input(" Objetivo (Enter para reconocimiento general) > ").strip()

    print(f"\n  Target  : {target}")
    print(f"  Objetivo: {objetivo or 'Reconocimiento general'}")
    print(f"  Dry-run : {'SÍ [WARN]' if args.dry_run else 'NO'}")

    orchestrator = NmapOrchestrator(
        target_ip   = target,
        objetivo    = objetivo,
        dry_run     = args.dry_run,
        nvd_api_key = args.nvd_key,
    )
    orchestrator.run()


# ──────────────────────────────────────────────────────────────────────────────
# MODO DEBSECAN
# ──────────────────────────────────────────────────────────────────────────────

def run_debsecan_mode(args):
    print(f"\n{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  MODO: ESCANEO DE PAQUETES (debsecan){RESET}")
    print(f"{CYAN}{'═'*60}{RESET}\n")

    if not check_tool("debsecan"):
        print(f"{YELLOW}[WARN]  debsecan no está instalado. Instalando...{RESET}")
        import subprocess
        subprocess.run(["sudo", "apt", "install", "-y", "debsecan"])

    try:
        from debsecan_mcp import run as debsecan_run
    except ImportError as e:
        print(f"{RED}[ERROR] Error importando debsecan_mcp: {e}{RESET}")
        sys.exit(1)

    suite = args.suite or ""
    only_fixed = args.only_fixed

    print(f"\n  Suite      : {suite or 'auto-detect'}")
    print(f"  Solo fixes : {only_fixed}")
    print(f"  NVD key    : {'yes' if args.nvd_key else 'No (rate limit reducido)'}")

    pdf = debsecan_run(suite=suite, only_fixed=only_fixed, nvd_api_key=args.nvd_key)
    if pdf:
        print(f"\n{GREEN}{'═'*60}{RESET}")
        print(f"{BOLD}{GREEN}  Scan complete{RESET}")
        print(f"{GREEN}  Report: {pdf}{RESET}")
        print(f"{GREEN}{'═'*60}{RESET}\n")


# ──────────────────────────────────────────────────────────────────────────────
# MODO LYNIS
# ──────────────────────────────────────────────────────────────────────────────

def run_lynis_mode(args):
    print(f"\n{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  MODO: AUDITORIA DEL SISTEMA (lynis){RESET}")
    print(f"{CYAN}{'═'*60}{RESET}\n")

    if not check_tool("lynis"):
        print(f"{YELLOW}[WARN]  lynis no está instalado. Instalando...{RESET}")
        import subprocess
        subprocess.run(["sudo", "apt", "install", "-y", "lynis"])

    try:
        from lynis_mcp import run as lynis_run
    except ImportError as e:
        print(f"{RED}[ERROR] Error importando lynis_mcp: {e}{RESET}")
        sys.exit(1)

    use_sudo = not args.no_sudo

    print(f"  Sudo       : {'Sí (análisis completo)' if use_sudo else 'No (análisis limitado)'}")
    print(f"  NVD key    : {'yes' if args.nvd_key else 'No (rate limit reducido)'}")

    pdf = lynis_run(use_sudo=use_sudo, nvd_api_key=args.nvd_key)
    if pdf:
        print(f"\n{GREEN}{'═'*60}{RESET}")
        print(f"{BOLD}{GREEN}  Audit complete{RESET}")
        print(f"{GREEN}  Report: {pdf}{RESET}")
        print(f"{GREEN}{'═'*60}{RESET}\n")


def run_cve_query_mode(args):
    print(f"\n{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  MODO: CONSULTA CVE (NVD + LLM){RESET}")
    print(f"{CYAN}{'═'*60}{RESET}\n")

    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "MCP"))
        from cve_query import run as cve_run
    except ImportError as e:
        print(f"{RED}[ERROR] Error importando cve_query: {e}{RESET}")
        sys.exit(1)

    cve_run(
        cve_id  = getattr(args, "cve", ""),
        search  = getattr(args, "search", ""),
        use_llm = not getattr(args, "no_llm", False),
        nvd_key = args.nvd_key,
    )


# ──────────────────────────────────────────────────────────────────────────────
# MENÚ INTERACTIVO
# ──────────────────────────────────────────────────────────────────────────────

def interactive_menu(args):
    print(BANNER)

    # Verificar dependencias Python
    missing = check_imports()
    if missing:
        print(f"{YELLOW}[WARN]  Dependencias Python faltantes: {', '.join(missing)}")
        print(f"   Instalar con: pip install {' '.join(missing)}{RESET}\n")

    # Estado de herramientas
    tools = {
        "nmap":     check_tool("nmap"),
        "ffuf":     check_tool("ffuf"),
        "debsecan": check_tool("debsecan"),
        "lynis":    check_tool("lynis"),
    }
    print("  Estado de herramientas:")
    for tool, ok in tools.items():
        icon = f"{GREEN}OK{RESET}" if ok else f"{YELLOW}[WARN]  (no instalado){RESET}"
        print(f"    {tool:10} {icon}")
    print()

    choice = _input("Selecciona modo [1/2/3] > ").strip()

    if choice == "1":
        run_nmap_mode(args)
    elif choice == "2":
        run_debsecan_mode(args)
    elif choice == "3":
        run_lynis_mode(args)
    elif choice == "4":
        run_cve_query_mode(args)
    else:
        print(f"{RED}Opción inválida.{RESET}")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Security Toolkit — nmap / debsecan / lynis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 main.py                                    # menú interactivo
  python3 main.py --mode nmap --target 10.129.7.3   # pentest directo
  python3 main.py --mode debsecan --only-fixed       # solo CVEs con fix
  python3 main.py --mode lynis --nvd-key ABC123      # auditoría con NVD
        """
    )

    # Modo de operación
    parser.add_argument("--mode", choices=["nmap", "debsecan", "lynis", "cve"],
                        help="Modo de operación")

    # Opciones nmap
    parser.add_argument("--target",   default="", help="[nmap] IP o rango objetivo")
    parser.add_argument("--objetivo", default="", help="[nmap] Objetivo del escaneo")
    parser.add_argument("--dry-run",  action="store_true", help="[nmap] Simular sin ejecutar")

    # Opciones debsecan
    parser.add_argument("--suite",      default="", help="[debsecan] Suite Debian (ej: bookworm)")
    parser.add_argument("--only-fixed", action="store_true",
                        help="[debsecan] Solo mostrar CVEs con fix disponible")

    # Opciones lynis
    parser.add_argument("--no-sudo", action="store_true",
                        help="[lynis] Ejecutar sin sudo (análisis limitado)")

    # Opciones cve
    parser.add_argument("--cve",    default="", help="[cve] CVE ID exacto (ej: CVE-2021-44228)")
    parser.add_argument("--search", default="", help="[cve] Búsqueda por producto (ej: vsftpd 3.0.3)")
    parser.add_argument("--no-llm", action="store_true", help="[cve] Solo datos NVD, sin LLM")

    # Compartidas
    parser.add_argument("--nvd-key", default="",
                        help="API key de NVD (opcional, aumenta rate limit)")

    args = parser.parse_args()

    if args.mode == "nmap":
        run_nmap_mode(args)
    elif args.mode == "debsecan":
        run_debsecan_mode(args)
    elif args.mode == "lynis":
        run_lynis_mode(args)
    elif args.mode == "cve":
        run_cve_query_mode(args)
    else:
        interactive_menu(args)


if __name__ == "__main__":
    main()
