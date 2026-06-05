#sudo apt update && sudo apt upgrade nmap
OUT_TXT="/home/pentest/Desktop/Marina/pentestM/RAG/INFO/ffuf_manual.txt"
echo "------ FFUF MANUAL AND HELP ------" > $OUT_TXT
man ffuf 2>/dev/null | col -b >> $OUT_TXT
ffuf --help >> $OUT_TXT