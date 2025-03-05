from flask import Flask, Response
import pandas as pd
import random

app = Flask(__name__)

# Generate synthetic threat intelligence dataset
data = {
    "ThreatID": range(1, 10001),  
    "ThreatScore": [round(random.uniform(0, 1), 2) for _ in range(10000)], 
    "AttackType": [random.choice(["DDoS", "Malware", "Phishing", "Ransomware"]) for _ in range(10000)] 
}

df = pd.DataFrame(data)

@app.route('/threat_data', methods=['GET'])
def get_csv():
    """
    Endpoint: /threat_data
    Method: GET
    Returns: Threat intelligence dataset in CSV format.
    """
    csv_data = df.to_csv(index=False)
    return Response(csv_data, mimetype="text/csv")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
