#!/usr/bin/env python3
"""
msf_manual_builder.py — ONE-TIME SETUP
Genera INFO/msf_manual.txt volcando todos los módulos exploit de Metasploit.
Ejecutar una vez antes de la primera operación, y al actualizar Metasploit.

Uso:
    python3 msf_manual_builder.py
    python3 msf_manual_builder.py --fast      # Solo searchsploit (más rápido)
    python3 msf_manual_builder.py --full      # Incluye msfconsole info por módulo (lento)
"""

import os
import sys
import json
import subprocess
import re
import time
import argparse
from pathlib import Path

# ── Constantes ────────────────────────────────────────────────────────────────
OUTPUT_DIR  = "INFO"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "msf_manual.txt")
MSF_MODULES_BASE = "/usr/share/metasploit-framework/modules"
ALT_MSF_PATH     = "/opt/metasploit-framework/modules"

# Ranks a incluir (excluye manual y low)
VALID_RANKS = {"excellent", "great", "good", "normal", "average"}

# Timeout para cada llamada a msfconsole
MSF_INFO_TIMEOUT = 25


def _check_tools():
    """Verificar que las herramientas necesarias están disponibles."""
    tools = {"msfconsole": False, "searchsploit": False}
    for tool in tools:
        try:
            result = subprocess.run(
                ["which", tool], capture_output=True, text=True, timeout=5
            )
            tools[tool] = result.returncode == 0
        except Exception:
            pass
    return tools


def _get_msf_modules_path():
    """Retorna el path base de módulos MSF disponible en este sistema."""
    if os.path.isdir(MSF_MODULES_BASE):
        return MSF_MODULES_BASE
    if os.path.isdir(ALT_MSF_PATH):
        return ALT_MSF_PATH
    # Intentar vía msfconsole
    return None


def _scan_modules_from_filesystem(msf_path: str) -> list:
    """
    Método rápido: escanea el filesystem para listar módulos exploit.
    Extrae metadatos básicos leyendo el archivo .rb directamente.
    """
    print("[*] Escaneando módulos desde filesystem...")
    modules = []

    exploits_path = os.path.join(msf_path, "exploits")
    if not os.path.isdir(exploits_path):
        print(f"[!] No se encuentra {exploits_path}")
        return modules

    rb_files = list(Path(exploits_path).rglob("*.rb"))
    print(f"[*] Encontrados {len(rb_files)} archivos .rb en exploits/")

    for rb_file in rb_files:
        try:
            content = rb_file.read_text(encoding="utf-8", errors="ignore")

            # Extraer nombre del módulo desde la ruta
            rel_path = str(rb_file.relative_to(msf_path))
            # exploits/unix/ftp/vsftpd_234_backdoor.rb → exploit/unix/ftp/vsftpd_234_backdoor
            module_path = "exploit/" + rel_path.replace("exploits/", "", 1).replace(".rb", "")

            # Extraer rank
            rank_match = re.search(r"Rank\s*=\s*(\w+Ranking|'\w+')", content)
            rank = "normal"
            if rank_match:
                rank_raw = rank_match.group(1).lower().replace("ranking", "").strip("'")
                rank = rank_raw

            if rank not in VALID_RANKS:
                continue

            # Extraer Name
            name_match = re.search(r"'Name'\s*=>\s*'([^']+)'", content)
            name = name_match.group(1) if name_match else module_path.split("/")[-1]

            # Extraer Description
            desc_match = re.search(r"'Description'\s*=>\s*%q\{([^}]+)\}", content, re.DOTALL)
            if not desc_match:
                desc_match = re.search(r"'Description'\s*=>\s*'([^']+)'", content)
            desc = desc_match.group(1).strip().replace("\n", " ")[:400] if desc_match else ""

            # Extraer Platform
            platform_match = re.search(r"'Platform'\s*=>\s*[\[']([^\]']+)", content)
            platform = platform_match.group(1) if platform_match else "unknown"

            # Extraer Arch
            arch_match = re.search(r"ARCH_\w+|'Arch'\s*=>\s*[\[']([^\]']+)", content)
            arch = arch_match.group(1) if arch_match and arch_match.lastindex else "unknown"

            # Extraer CVEs
            cves = re.findall(r"CVE[',\s-]+(\d{4})[',\s-]+(\d+)", content)
            cve_list = [f"CVE-{year}-{num}" for year, num in cves[:8]]

            # Extraer fecha de disclosure
            date_match = re.search(r"'DisclosureDate'\s*=>\s*'([^']+)'", content)
            date_str = date_match.group(1) if date_match else ""

            # Extraer targets
            targets_raw = re.findall(r"\['([^']{3,60})',\s*\{", content)
            targets = targets_raw[:5]

            modules.append({
                "path": module_path,
                "name": name,
                "rank": rank,
                "platform": platform,
                "arch": arch,
                "cves": cve_list,
                "description": desc,
                "targets": targets,
                "date": date_str,
            })

        except Exception as e:
            continue

    print(f"[*] Módulos válidos extraídos: {len(modules)}")
    return modules


def _get_searchsploit_data() -> dict:
    """
    Obtiene datos de searchsploit como fuente complementaria.
    Retorna dict: cve_id → lista de dicts {title, path, type}
    """
    print("[*] Consultando searchsploit --json...")
    cve_map = {}
    try:
        result = subprocess.run(
            ["searchsploit", "--json", ""],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            for exploit in data.get("RESULTS_EXPLOIT", []):
                title = exploit.get("Title", "")
                cves_found = re.findall(r"CVE-(\d{4}-\d+)", title)
                for cve in cves_found:
                    cve_key = f"CVE-{cve}"
                    if cve_key not in cve_map:
                        cve_map[cve_key] = []
                    cve_map[cve_key].append({
                        "title": title,
                        "path": exploit.get("Path", ""),
                        "type": exploit.get("Type", ""),
                    })
    except Exception as e:
        print(f"[!] searchsploit falló: {e}")
    print(f"[*] searchsploit: {len(cve_map)} CVEs indexados")
    return cve_map


def _format_module_chunk(mod: dict, searchsploit_data: dict = None) -> str:
    """Formatea un módulo como chunk de texto para el RAG."""
    cve_str = ", ".join(mod["cves"]) if mod["cves"] else "none"
    targets_str = " | ".join(mod["targets"]) if mod["targets"] else "generic"

    # Buscar info adicional de searchsploit para los CVEs de este módulo
    sploit_extra = ""
    if searchsploit_data and mod["cves"]:
        for cve in mod["cves"][:3]:
            if cve in searchsploit_data:
                for entry in searchsploit_data[cve][:2]:
                    sploit_extra += f"\n  SEARCHSPLOIT: {entry['title']}"

    chunk = (
        f"---- MÓDULO: {mod['path']} ----\n"
        f"NAME: {mod['name']}\n"
        f"RANK: {mod['rank']}\n"
        f"PLATFORM: {mod['platform']}\n"
        f"ARCH: {mod['arch']}\n"
        f"DATE: {mod['date']}\n"
        f"CVEs: {cve_str}\n"
        f"TARGETS: {targets_str}\n"
        f"DESC: {mod['description']}{sploit_extra}\n"
    )
    return chunk


def build_msf_manual(fast_mode: bool = True, full_mode: bool = False):
    """Función principal que construye INFO/msf_manual.txt."""
    print("\n" + "="*60)
    print("  msf_manual_builder.py — Generando base RAG MSF")
    print("="*60 + "\n")

    # Crear directorio INFO si no existe
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    tools = _check_tools()
    print(f"[*] msfconsole disponible: {tools['msfconsole']}")
    print(f"[*] searchsploit disponible: {tools['searchsploit']}")

    if not tools["msfconsole"]:
        print("[!] FATAL: msfconsole no encontrado. Instala Metasploit Framework.")
        sys.exit(1)

    modules = []
    searchsploit_data = {}

    # Fuente 1: Filesystem (rápido, ~5 segundos)
    msf_path = _get_msf_modules_path()
    if msf_path:
        modules = _scan_modules_from_filesystem(msf_path)
    else:
        print("[!] No se encontró el directorio de módulos MSF en rutas estándar.")
        print("[!] Intentando con msfconsole search (lento)...")
        # Fallback: usar msfconsole search
        try:
            result = subprocess.run(
                ["msfconsole", "-q", "-x", "search type:exploit; exit"],
                capture_output=True, text=True, timeout=180
            )
            # Parse básico de la tabla de módulos
            for line in result.stdout.splitlines():
                m = re.match(r"\s+(\d+)\s+(exploit/\S+)\s+\S+\s+(\w+)\s+(.+)", line)
                if m:
                    modules.append({
                        "path": m.group(2),
                        "name": m.group(4).strip(),
                        "rank": m.group(3).lower(),
                        "platform": "unknown",
                        "arch": "unknown",
                        "cves": [],
                        "description": m.group(4).strip(),
                        "targets": [],
                        "date": "",
                    })
            print(f"[*] msfconsole search retornó {len(modules)} módulos")
        except Exception as e:
            print(f"[!] msfconsole search falló: {e}")
            sys.exit(1)

    # Fuente 2: searchsploit (si está disponible)
    if tools["searchsploit"]:
        searchsploit_data = _get_searchsploit_data()

    # Generar el archivo de texto
    print(f"\n[*] Generando {OUTPUT_FILE}...")
    total = len(modules)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# MSF MANUAL — BASE RAG METASPLOIT\n")
        f.write(f"# Generado: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total módulos: {total}\n")
        f.write(f"# Ranks incluidos: {', '.join(VALID_RANKS)}\n")
        f.write("# Formato: ---- MÓDULO: path ---- (separador de chunks)\n\n")

        for i, mod in enumerate(modules):
            if i % 500 == 0 and i > 0:
                print(f"    [{i}/{total}] procesando...")
            chunk = _format_module_chunk(mod, searchsploit_data)
            f.write(chunk + "\n")

    size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    print(f"\n[✓] {OUTPUT_FILE} generado")
    print(f"[✓] Tamaño: {size_mb:.1f} MB")
    print(f"[✓] Módulos: {total}")
    print(f"\n[!] SIGUIENTE PASO: ejecutar 'ollama create msfgpt -f msf_modelfile'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Genera INFO/msf_manual.txt para el RAG MSF")
    parser.add_argument("--fast", action="store_true", default=True,
                        help="Modo rápido: solo filesystem + searchsploit (default)")
    parser.add_argument("--full", action="store_true", default=False,
                        help="Modo completo: incluye msfconsole info por módulo (muy lento)")
    args = parser.parse_args()

    build_msf_manual(fast_mode=args.fast, full_mode=args.full)
