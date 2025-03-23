from flask import Flask, jsonify

app = Flask(__name__)

# Home route (checks if API is running)
@app.route("/")
def home():
    return jsonify({"message": "Flask API is running!"})

# ✅ Fix: Add missing /data route
@app.route("/data", methods=["GET"])
def get_data():
    sample_data = [
        {"region": "Scotland", "threat_count": 450, "severity": 0.87},
        {"region": "England", "threat_count": 780, "severity": 0.65}
    ]
    return jsonify(sample_data)

if __name__ == "__main__":
    app.run(debug=True)
