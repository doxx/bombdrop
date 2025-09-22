while true; do echo -n "$(date '+%Y-%m-%d %H:%M:%S'),"; top -l 4 | egrep "mDNSResponder|kernel_task" | grep -v Hel | tail -2 | awk '{print $3}' | tr '\n' ',' | sed 's/,$/\n/'; sleep 1; done
