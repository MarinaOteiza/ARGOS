import re

def load_chunks_nmap(filepath):
    chunks = []
    
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # ── Bloque 1: extraer sección de flags del man/help ──────────────
    # Busca líneas que empiecen por "-" (flags) y las agrupa con su descripción
    help_section = re.findall(
        r'(-{1,2}[\w\-]+(?:\s[\w<>\[\]\.]+)*.*?(?:\n(?!\s*-{1,2}).*)*)',
        content
    )
    for match in help_section:
        chunk = match.strip()
        if len(chunk) > 40:  # descartar líneas muy cortas
            chunks.append(chunk)

    # ── Bloque 2: extraer cada script NSE como chunk independiente ───
    # El separador es "---- /usr/share/nmap/scripts/xxxx.nse ----"
    script_blocks = re.split(r'---- /usr/share/nmap/scripts/', content)
    
    for block in script_blocks[1:]:  # el primero es cabecera, lo saltamos
        lines = block.strip().split("\n")
        script_name = lines[0].replace("----", "").strip()  # nombre del .nse
        body = "\n".join(lines[1:]).strip()
        
        if body:
            chunk = f"Script NSE: {script_name}\n{body}"
            # Limitamos tamaño para no saturar el contexto
            chunks.append(chunk[:1000])
    
    return chunks