import re

def analyze_log(file_path):
    failed_logins = 0
    suspicious_ips = {}

    with open(file_path, "r") as f:
        for line in f:
            # Look for "Failed password" like in Linux auth logs
            if "Failed password" in line:
                failed_logins += 1
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    print(f"Total failed login attempts: {failed_logins}")
    if suspicious_ips:
        print("Top suspicious IPs:")
        for ip, count in suspicious_ips.items():
            print(f"{ip}: {count} attempts")

if __name__ == "__main__":
    log_file = "sample_logs.txt"  # Default test file
    analyze_log(log_file)
