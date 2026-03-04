import json
from collections import Counter

log_file = "logs/sentinel.log"

categories = Counter()
ips = Counter()
total = 0
blocked = 0

with open(log_file) as f:
    for line in f:
        total += 1
        entry = json.loads(line)
        ips[entry["ip"]] += 1
        if entry["action"] == "BLOCK":
            blocked += 1
            categories[entry["category"]] += 1

print("Total Requests:", total)
print("Blocked Requests:", blocked)
print("Detection Accuracy:", round((blocked/total)*100,2), "%")
print("Top Categories:", categories.most_common())
print("Top IPs:", ips.most_common(5))
