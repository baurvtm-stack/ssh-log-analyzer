import sys

counts = {}
THRESHOLD = 3

try:
    with open("auth.log.ba") as f:
        for x in f:
            if "Failed password" in x:
                words = x.split()
                idx =words.index("from")
                ip = words[idx + 1]
                if ip in counts:
                    counts[ip] += 1
                else:
                    counts[ip] = 1
except FileNotFoundError:
    print("[!] Error: file 'auth.log' not found. Make sure it exists in the current directory.")
    sys.exit(1)

sorted_ips = sorted(counts.items(),key=lambda pair: pair[1], reverse= True)

print("[!] Suspicious login activity detected:")

for ip, count in sorted_ips:
    flag = "[BRUTE FORCE SUSPECTED]" if count >= THRESHOLD else ""
    print(f"{ip} --> {count} failed attempts {flag}")
