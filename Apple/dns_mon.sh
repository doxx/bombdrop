#!/bin/csh
while true; do echo -n "$(date '+%Y-%m-%d %H:%M:%S'),"; start=$(gdate +%s%N); if timeout 3 dscacheutil -q host -a name www.google.com >/dev/null; then echo $(($(gdate +%s%N) - start)) | awk '{printf "%.1f\n", $1/1000000}'; else echo ""; fi; sleep 4; done 
