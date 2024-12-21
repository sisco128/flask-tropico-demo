from flask import Flask, request, jsonify
import random
import uuid
import time
from datetime import datetime
import os

app = Flask(__name__)

# In-memory storage for scan states and domains
scans = {}
domains = {}

# Bearer Token (replace with a secure method, such as environment variable)
BEARER_TOKEN = os.environ.get("BEARER_TOKEN", "your-siscolino-bearer-token")

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
def generate_endpoints(domain_name):
    frameworks = ["Django", "Express", "Spring Boot", "Flask", "Laravel"]
    api_types = ["JSON-API", "HTML WEB"]
    environments = ["Production", "Staging", "Development"]
    
    endpoints = []
    for _ in range(random.randint(3, 10)):
        endpoint = {
            "endpoint_uid": generate_uid(),
            "endpoint_name": f"/api/v1/{random.choice(['users', 'orders', 'payments', 'products', 'inventory'])}",
            "hostname": f"{random.choice(['api', 'orders', 'payments'])}.{domain_name}",
            "environment": random.choice(environments),
            "framework": random.choice(frameworks),
            "api_type": random.choice(api_types),
            "risk_factors": random_risk_factors(),
        }
        endpoints.append(endpoint)
    return endpoints

# Middleware to validate Bearer Token
def validate_bearer_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized. Missing or invalid token."}), 401
    
    token = auth_header.split(" ")[1]
    if token != BEARER_TOKEN:
        return jsonify({"error": "Unauthorized. Invalid token."}), 403

# Root route for health check
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Tropico Demo API is running!"}), 200

# Endpoint 1: Create Account
@app.route("/account/", methods=["POST"])
def create_account():
    auth_response = validate_bearer_token()
    if auth_response: return auth_response

    if not request.is_json:
        return jsonify({"error": "Invalid content type"}), 400

    account_uid = generate_uid()
    return jsonify({"account_uid": account_uid}), 200

# Endpoint 2: Add Domain
@app.route("/account/<account_uid>/domain", methods=["POST"])
def add_domain(account_uid):
    auth_response = validate_bearer_token()
    if auth_response: return auth_response

    if not request.is_json:
        return jsonify({"error": "Invalid content type"}), 400

    data = request.get_json()
    if "domain_name" not in data:
        return jsonify({"error": "Missing domain name"}), 400

    domain_uid = generate_uid()
    # Store the domain name with the domain_uid
    domains[domain_uid] = {
        "account_uid": account_uid,
        "domain_name": data["domain_name"]
    }
    return jsonify({"domain_uid": domain_uid}), 200

# Endpoint 3: Request Domain Scan
@app.route("/account/<account_uid>/domain/<domain_uid>/scan", methods=["POST"])
def request_scan(account_uid, domain_uid):
    auth_response = validate_bearer_token()
    if auth_response: return auth_response

    if domain_uid not in domains:
        return jsonify({"error": "Domain not found"}), 404

    scan_uid = generate_uid()
    scans[scan_uid] = {
        "status": "pending",
        "domain_uid": domain_uid,
        "name": domains[domain_uid]["domain_name"],  # Fetch domain name
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "start_time": time.time(),
    }
    return jsonify({"scan_uid": scan_uid}), 200

# Endpoint 4: Check Scan Status by Account ID, Domain ID, and Scan ID
@app.route("/account/<account_uid>/domain/<domain_uid>/scan/<scan_uid>", methods=["GET"])
def check_scan_status(account_uid, domain_uid, scan_uid):
    auth_response = validate_bearer_token()
    if auth_response: return auth_response

    # Fetch scan data using scan_uid
    scan_data = scans.get(scan_uid)
    if not scan_data or scan_data["domain_uid"] != domain_uid:
        return jsonify({"error": "Scan not found"}), 404

    # Check if the pending period (5 seconds) is over
    if time.time() - scan_data["start_time"] > 5:
        # Generate completed scan result
        scan_data["status"] = "completed"
        scan_data["endpoints"] = generate_endpoints(scan_data["name"])  # Use domain name for hostname

    # Return the scan data
    if scan_data["status"] == "pending":
        return jsonify({
            "scan_status": "pending",
            "domain": {
                "domain_uid": scan_data["domain_uid"],
                "name": scan_data["name"],  # Use the stored domain name
                "timestamp": scan_data["timestamp"],
            }
        }), 200
    
    elif scan_data["status"] == "completed":
        return jsonify({
            "scan_status": "completed",
            "domain": {
                "domain_uid": scan_data["domain_uid"],
                "name": scan_data["name"],  # Use the stored domain name
                "timestamp": scan_data["timestamp"],
                "endpoints": scan_data["endpoints"],  # Includes domain-specific hostname
            }
        }), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use the PORT environment variable for deployment
    app.run(host="0.0.0.0", port=port)
