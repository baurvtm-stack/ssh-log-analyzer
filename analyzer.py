import sys

if len(sys.argv) < 2:
        print("Usage: python analyzer.py <logfile>")
        sys.exit(1)

log_file = sys.argv[1]
THRESHOLD = 3
def parse_log(log_file):
    counts = {}
    try:
        with open(log_file) as f:
            for x in f:
                if "Failed password" in x:
                    words = x.split()
                    try:
                        idx = words.index("from")
                        ip = words[idx + 1]
                        if ip in counts:
                            counts[ip] += 1
                        else:
                            counts[ip] = 1
                    except (ValueError, IndexError):
                            continue
    except FileNotFoundError: 
            print(
                f"[!] Error: file {log_file} not found. Make sure it exists in the current directory."
            )
            sys.exit(1)
    return counts
def print_report(counts):
    sorted_ips = sorted(counts.items(), key=lambda pair: pair[1], reverse=True)
    print("[!] Suspicious login activity detected:")
    for ip, count in sorted_ips:
        flag = "[BRUTE FORCE SUSPECTED]" if count >= THRESHOLD else ""
        print(f"{ip} --> {count} failed attempts {flag}")


def main():
    if len(sys.argv) < 2:
            print("Usage: python analyzer.py <logfile>")
            sys.exit(1)

    log_file = sys.argv[1]
    counts = parse_log(log_file)
    print_report(counts)

if __name__ == "__main__":
    main()