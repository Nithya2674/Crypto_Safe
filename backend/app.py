from flask import Flask, request, jsonify
from flask_cors import CORS

from analyzer.scanner import scan_code_full, get_registered_rules, auto_fix_code


app = Flask(__name__)

CORS(app)


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "CryptoAPI-Safe API is running",
        "version": "2.0.0",
        "engine": "Modular AST Rule Engine",
        "rules_count": len(get_registered_rules())
    })


@app.route("/api/rules", methods=["GET"])
def list_rules():
    """Returns the catalog of all active cryptographic security rules."""
    rules = get_registered_rules()
    return jsonify({
        "success": True,
        "total_rules": len(rules),
        "rules": rules
    })


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "error": "Request body is missing."
        }), 400

    code = data.get("code", "")

    if not code.strip():
        return jsonify({
            "success": False,
            "error": "No code provided."
        }), 400

    result = scan_code_full(code)

    return jsonify({
        "success": result.get("success", True),
        "findings": result.get("findings", []),
        "total_findings": result.get("total_findings", len(result.get("findings", []))),
        "readiness_score": result.get("readiness_score", 0),
        "grade": result.get("grade", "F"),
        "cbom": result.get("cbom", []),
        "summary": result.get("summary", {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }),
        "error": result.get("error")
    })


@app.route("/api/fix", methods=["POST"])
def fix():
    """Applies automated remediation and returns the remediated code and diff."""
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "error": "Request body is missing."
        }), 400

    code = data.get("code", "")

    if not code.strip():
        return jsonify({
            "success": False,
            "error": "No code provided."
        }), 400

    fix_result = auto_fix_code(code)

    return jsonify(fix_result)



if __name__ == "__main__":
    print("\n====================================")
    print("       CryptoAPI-Safe Backend v2.0")
    print("   Modular Post-Quantum Rule Engine")
    print("====================================")
    print(f"Loaded Rules: {len(get_registered_rules())}")
    print("Server: http://127.0.0.1:5000")
    print("====================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
