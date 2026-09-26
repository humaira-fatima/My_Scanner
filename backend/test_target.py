from flask import Flask, request, jsonify, render_template_string, make_response

app = Flask(__name__)

# ==========================================
# 1. PASSIVE RECON & JS MINER TARGET
# ==========================================
@app.route("/static/app.bundle.js")
def serve_bundled_js():
    """
    Minified frontend JS bundle containing obfuscated API keys, 
    internal staging URLs, and hidden admin endpoints.
    """
    js_content = """
    (function(){
        const _0x9a=["https://internal-api-staging.corp.local/v3","sk_live_99A82B3C4D5E6F7G8H9I0J","AKIAIOSFODNN7EXAMPLE"];
        window.__CONFIG__ = {
            env: "production",
            apiBase: "/api/v1",
            hiddenVault: "/admin_v2_vault/dashboard",
            stripeSecret: _0x9a[1],
            awsAccessKey: _0x9a[2],
            endpoints: [
                "/api/v1/users/1",
                "/api/v2/orgs/101/docs/505",
                "/api/v1/checkout/confirm",
                "/api/v1/xml/process"
            ]
        };
        console.log("Application bundle loaded.");
    })();
    """
    res = make_response(js_content)
    res.headers["Content-Type"] = "application/javascript"
    return res


# ==========================================
# 2. MAIN PORTAL & DOM SCANNER SINK
# ==========================================
@app.route("/")
def index():
    """
    Serves the target homepage featuring a DOM XSS sink reading from location.hash.
    """
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hardened Security Testbed</title>
        <script src="/static/app.bundle.js"></script>
    </head>
    <body>
        <h1>Enterprise Core Target Portal</h1>
        <div id="user-display"></div>
        
        <!-- DOM XSS Sink -->
        <script>
            const urlHash = decodeURIComponent(window.location.hash.substring(1));
            if (urlHash) {
                document.getElementById('user-display').innerHTML = "Current User context: " + urlHash;
            }
        </script>
    </body>
    </html>
    """


# ==========================================
# 3. ACTIVE XSS TARGET (Context Injection)
# ==========================================
@app.route("/search")
def search():
    """
    Reflects query input inside both an HTML attribute and an inline JS string variable,
    requiring payload tag breaking or attribute escaping.
    """
    query = request.args.get("q", "")
    return render_template_string(f"""
    <!DOCTYPE html>
    <html>
    <body>
        <h2>Search System</h2>
        <form action="/search" method="GET">
            <input type="text" name="q" value="{query}">
            <button type="submit">Search</button>
        </form>
        <script>
            var searchContext = "{query}";
        </script>
    </body>
    </html>
    """)


# ==========================================
# 4. ADVANCED BOLA / IDOR ENGINE TARGETS
# ==========================================
@app.route("/api/v1/users/<user_id>", methods=["GET"])
def get_user_profile(user_id):
    """
    Standard BOLA flaw: Accepts ANY valid Bearer token (Token B) and exposes User A's secrets.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return jsonify({"error": "Unauthorized session missing"}), 401

    return jsonify({
        "id": int(user_id),
        "username": "user_a",
        "email": "victim_a@corp.internal",
        "secret_api_key": "LIVE_SECRET_KEY_12345",
        "role": "admin"
    }), 200


@app.route("/api/v2/orgs/<org_id>/docs/<doc_id>", methods=["GET"])
def get_nested_org_doc(org_id, doc_id):
    """
    Nested BOLA flaw: Multi-parameter object access bypass.
    """
    return jsonify({
        "org_id": org_id,
        "doc_id": doc_id,
        "owner": "corporate_treasury",
        "confidential_data": "CONFIDENTIAL_PAYROLL_2026.XLSX"
    }), 200


# ==========================================
# 5. OWASP BUSINESS LOGIC TARGET
# ==========================================
@app.route("/api/v1/checkout/confirm", methods=["POST"])
def checkout_confirm():
    """
    Business Logic Flaw: Accepts negative quantity or zero price values.
    """
    data = request.get_json(silent=True) or {}
    price = data.get("price", 100)
    quantity = data.get("quantity", 1)

    if price <= 0 or quantity <= 0:
        return jsonify({
            "status": "success",
            "vulnerability": "Business Logic Parameter Tampering Detected",
            "total_charged": price * quantity
        }), 200

    return jsonify({"status": "processed", "total": price * quantity}), 200


# ==========================================
# 6. XXE / XML ENGINE TARGET
# ==========================================
@app.route("/api/v1/xml/process", methods=["POST"])
def process_xml():
    """
    XXE Flaw: Detects external entity expansion payloads in POST data.
    """
    xml_data = request.data.decode("utf-8", errors="ignore")
    if "ENTITY" in xml_data or "SYSTEM" in xml_data:
        return jsonify({
            "status": "vulnerable",
            "title": "XML External Entity (XXE) Injection",
            "extracted_file": "root:x:0:0:root:/root:/bin/bash"
        }), 200

    return jsonify({"status": "parsed"}), 200


if __name__ == "__main__":
    print("[*] Launching Hardened Flask Mock Target on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)