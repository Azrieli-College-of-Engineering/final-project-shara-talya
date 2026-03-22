from flask import Flask, request, jsonify
import jwt
import os

app = Flask(__name__)

# מפתח סודי (במציאות הוא צריך להיות שמור היטב, כאן הוא לצורך ההדגמה)
SECRET_KEY = "super-secret-key-123"


# 1. Endpoint להתחברות - מחזיר JWT סטנדרטי
@app.route('/login', methods=['POST'])
def login():
    # לצורך ה-POC, נניח שהתחברות תמיד מצליחה כמשתמש רגיל
    payload = {
        "user": "guest_user",
        "role": "user"
    }

    # יצירת טוקן חתום באלגוריתם HS256
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})


# 2. Endpoint הפגיע - כאן קורה ה-Bypass
@app.route('/api/jwt-inspect', methods=['GET'])
def inspect_jwt():
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return jsonify({"error": "Missing token"}), 401

    try:
        # הסרת המילה 'Bearer ' מההדר אם קיימת
        token = auth_header.split(" ")[1] if " " in auth_header else auth_header

        # החולשה: שימוש ב-jwt.decode ללא אימות חתימה (options={"verify_signature": False})
        # או פשוט אי-הגדרת אלגוריתמים מותרים [cite: 6, 50, 53]
        decoded_payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256", "none"],
            options={"verify_signature": False}
        )

        user_role = decoded_payload.get("role")

        if user_role == "admin":
             return jsonify({
            "message": "Access Granted! Welcome Admin.",
            "data": decoded_payload
            }), 200
        else:
            return jsonify({
                "message": f"Access Denied. Role '{user_role}' has no admin privileges.",
                "data": decoded_payload
            }), 403

    except Exception as e:
        return jsonify({"error": str(e)}), 400



#another kind of JWT attack
@app.route('/api/kid-inspect', methods=['GET'])
def kid_inspect():

    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return jsonify({"error": "Missing token"}), 401

    token = auth_header.split(" ")[1]

    try:
        # נקרא את ה-header בלי אימות
        header = jwt.get_unverified_header(token)

        kid = header.get("kid")

        print("KID =", kid)

        # ❌ קוד פגיע
        key_path = os.path.join("keys", kid)

        print("JOIN PATH =", key_path)
        print("ABS PATH =", os.path.abspath(key_path))

        with open(key_path, "r") as f:
            key = f.read().strip()

        decoded = jwt.decode(
            token,
            key,
            algorithms=["HS256"]
        )

        role = decoded.get("role")

        if role == "admin":
            return jsonify({
                "message": "Admin access",
                "data": decoded,
                "key_used": key
            })

        return jsonify({
            "message": "Not admin",
            "data": decoded,
            "key_used": key
        })

    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    app.run(debug=True, port=5000)