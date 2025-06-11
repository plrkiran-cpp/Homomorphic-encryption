import csv
import random
import time
from datetime import datetime, timedelta

def generate_random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_random_timestamp():
    now = int(time.time())
    past = now - 60 * 60 * 24 * 30  # last 30 days
    return random.randint(past, now)

def generate_threat_dataset(filename, num_records=100000):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['ThreatScore', 'AttackType', 'Timestamp', 'SourceIP'])

        for _ in range(num_records):
            score = round(random.uniform(0.0, 1.0), 4)
            attack_type = random.choice([0, 1, 2])
            timestamp = generate_random_timestamp()
            ip_address = generate_random_ip()
            writer.writerow([score, attack_type, timestamp, ip_address])

    print(f" Dataset saved as '{filename}' with {num_records} records.")

if __name__ == "__main__":
    generate_threat_dataset("dataset/threat_dataset_100k.csv", 100000)
