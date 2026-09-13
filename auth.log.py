counts = {}
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
    print(counts)