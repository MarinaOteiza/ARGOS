#sudo apt update && sudo apt upgrade nmap
OUT_TXT="/home/pentest/Desktop/Marina/pentestM/RAG/INFO/nmap_manual.txt"
echo "------ NMAP MANUAL AND HELP ------" > $OUT_TXT
man nmap 2>/dev/null | col -b >> $OUT_TXT
nmap --help >> $OUT_TXT
echo "------ NMAP GLOBAL SCRIPTS ------" >> $OUT_TXT
nmap --script-help "*" >> $OUT_TXT
echo "------ NMAP DETAILED SCRIPTS ------" >> $OUT_TXT
for s in /usr/share/nmap/scripts/*.nse; do
    echo "---- $s ----" >> "$OUT_TXT"
    nmap --script-help "$s" >> "$OUT_TXT" 2>/dev/null
done
