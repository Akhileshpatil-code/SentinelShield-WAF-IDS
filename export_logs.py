import json
import csv

log_file = "logs/sentinel.log"
csv_file = "logs/sentinel_report.csv"

with open(log_file) as infile, open(csv_file, "w", newline="") as outfile:
    writer = csv.writer(outfile)
    writer.writerow(["Timestamp","IP","Method","Path","Category","Action","Reason"])

    for line in infile:
        entry = json.loads(line)
        writer.writerow([
            entry.get("ts"),
            entry.get("ip"),
            entry.get("method"),
            entry.get("path"),
            entry.get("category"),
            entry.get("action"),
            entry.get("reason")
        ])

print("CSV Report Generated:", csv_file)
