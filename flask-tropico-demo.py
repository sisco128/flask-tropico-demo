from flask import Flask, request, jsonify
import random
import uuid
import time
from datetime import datetime

app = Flask(__name__)

# In-memory storage for scan states
scans = {}

# Helper function to generate random UIDs
def generate_uid():
    return str(uuid.uuid4())

# Helper function to generate random risk factors
def random_risk_factors():
    risk_factors = [
        "Broken Object-Level Authorization (BOLA)",
        "Broken User Authentication",
        "Excessive Data Exposure",
        "Lack of Resources & Rate Limiting",
        "Broken Function-Level Authorization",
        "Mass Assignment",
        "Security Misconfiguration",
        "Injection",
        "Improper Assets Management",
        "Internet Exposure",
        "Sensitive Data Exposure",
        "Deprecated or Zombie APIs",
        "Documentation Completeness",
        "Authentication and Authorization Gaps",
        "Rate Limiting and Abuse Protection",
    ]
    return random.sample(risk_factors, random.randint(1, 5))

# Helper function to generate randomized endpoint details
def generate_endpoints():
    frameworks = ["Django", "Express", "Spring Boot", "Flask", "Laravel"]
    api_types = ["REST", "GraphQL", "SOAP"]
    environments = ["Production", "Staging", "Development"]
    
    endpoints = []
    for _ in range(random.randint(1, 5)):
        endpoint = {
            "endpoint_uid": generate_uid(),
            "endpoint_name": f"/api/v1/{random.choice(['users', 'orders', 'payments', 'products', 'inventory'])}",
            "hostname": f"{random.choice(['api', 'orders', 'payments'])}.example.com",
            "environment": random.choice(environments),
            "framework": random.choice(frameworks),
            "api_type": random.choice(api_types),
            "risk_factors": random_risk_factors(),
        }
        endpoints.append(endpoint)
    return endpoints

# Endpoint 1: Create Account
@app.route("/account/", methods=["POST"])
def create_account():
    if not request.is_json:
        return jsonify({"error": "Invalid content type"}), 400

    account_uid = generate_uid()
    return jsonify({"account_uid": account_uid}), 200

# Endpoint 2: Add Domain
@app.route("/account/<account_uid>/domain", methods=["POST"])
def add_domain(account_uid):
    if not request.is_json:
        return jsonify({"error": "Invalid content type"}), 400

    data = request.get_json()
    if "domain_name" not in data:
        return jsonify({"error": "Missing domain name"}), 400

    domain_uid = generate_uid()
    return jsonify({"domain_uid": domain_uid}), 200

# Endpoint 3: Request Domain Scan
@app.route("/account/<account_uid>/domain/<domain_uid>/scan", methods=["POST"])
def request_scan(account_uid, domain_uid):
    scan_uid = generate_uid()
    scans[scan_uid] = {
        "status": "pending",
        "domain_uid": domain_uid,
        "name": "example.com",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "start_time": time.time(),
    }
    return jsonify({"scan_uid": scan_uid}), 200

# Endpoint 4: Check Scan Status
@app.route("/account/<account_uid>/domain/<domain_uid>/scan", methods=["GET"])
def check_scan_status(account_uid, domain_uid):
    # Assume the scan_uid is derived from the domain_uid
    for scan_uid, scan_data in scans.items():
        if scan_data["domain_uid"] == domain_uid:
            # Check if the pending period (5 seconds) is over
            if time.time() - scan_data["start_time"] > 5:
                # Generate completed scan result
                scan_data["status"] = "completed"
                scan_data["endpoints"] = generate_endpoints()
            
            if scan_data["status"] == "pending":
                return jsonify({
                    "scan_status": "pending",
                    "domain": {
                        "domain_uid": scan_data["domain_uid"],
                        "name": scan_data["name"],
                        "timestamp": scan_data["timestamp"],
                    }
                }), 200
            
            elif scan_data["status"] == "completed":
                return jsonify({
                    "scan_status": "completed",
                    "domain": {
                        "domain_uid": scan_data["domain_uid"],
                        "name": scan_data["name"],
                        "timestamp": scan_data["timestamp"],
                        "endpoints": scan_data["endpoints"],
                    }
                }), 200

    return jsonify({"error": "Scan not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
