import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("logs/sentinel_report.csv")

# Count attack categories
attack_counts = df[df["Action"]=="BLOCK"]["Category"].value_counts()

plt.figure(figsize=(6,6))
attack_counts.plot(kind="pie", autopct="%1.1f%%")
plt.title("Attack Category Distribution")
plt.ylabel("")
plt.savefig("logs/attack_distribution.png")
plt.close()

# Top IPs
ip_counts = df["IP"].value_counts().head(5)

plt.figure()
ip_counts.plot(kind="bar")
plt.title("Top IP Activity")
plt.ylabel("Requests")
plt.savefig("logs/top_ips.png")
plt.close()

print("Charts Generated in logs/")
