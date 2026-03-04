import pandas as pd

df = pd.read_csv("sentinel_report.csv")

total = len(df)
blocked = len(df[df["Decision"] == "Blocked"])

accuracy = (blocked / total) * 100 if total > 0 else 0

print(f"Total Requests: {total}")
print(f"Blocked Requests: {blocked}")
print(f"Detection Accuracy: {accuracy:.2f}%")
