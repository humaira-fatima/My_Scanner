from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock database: User A (ID 1) and User B (ID 2)
USERS_DB = {
    "1": {"id": 1, "username": "alice", "email": "alice@example.com", "secret": "ALICE_CONFIDENTIAL_123"},
    "2": {"id": 2, "username": "bob", "email": "bob@example.com", "secret": "BOB_CONFIDENTIAL_999"}
}

# Valid tokens mapping
VALID_TOKENS = {
    "token_user_a": "1",
    "token_user_b": "2"
}

@app.route('/api/v1/users/<user_id>', methods=['GET'])
def get_user_profile(user_id):
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    
    # 1. Authentication Check
    if not auth_token or auth_token not in VALID_TOKENS:
        return jsonify({"error": "Unauthorized"}), 401
    
    # 2. BOLA VULNERABILITY:
    # Verifies token validity, but fails to check if token matches user_id.
    if user_id in USERS_DB:
        return jsonify(USERS_DB[user_id]), 200
        
    return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    print("Running BOLA Target on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000)
