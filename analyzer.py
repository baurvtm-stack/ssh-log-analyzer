counts = {}
THRESHOLD = 3
with open("auth.log") as f:
    for x in f:
        if "Failed password" in x:
            words = x.split()
            idx =words.index("from")
            ip = words[idx + 1]
            if ip in counts:
                counts[ip] += 1
            else:
                counts[ip] = 1
sorted_ips = sorted(counts.items(),key=lambda pair: pair[1], reverse= True)

print("[!] Suspicious login activity detected:")

for ip, count in sorted_ips:
    flag = "[BRUTE FORCE SUSPECTED]" if count >= THRESHOLD else ""
    print(f"{ip} --> {count} failed attempts {flag}")