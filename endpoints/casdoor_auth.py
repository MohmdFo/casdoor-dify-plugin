import os
import urllib.parse
import requests
import jwt

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from flask import redirect, request, Response, jsonify
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Retrieve credentials from environment variables
CASDOOR_CERT = os.getenv("CASDOOR_CERT")
CASDOOR_ENDPOINT = os.getenv("CASDOOR_ENDPOINT")
CASDOOR_CLIENT_ID = os.getenv("CASDOOR_CLIENT_ID")
CASDOOR_CLIENT_SECRET = os.getenv("CASDOOR_CLIENT_SECRET")
CASDOOR_ORG_NAME = os.getenv("CASDOOR_ORG_NAME")
CASDOOR_APP_NAME = os.getenv("CASDOOR_APP_NAME")


def get_casdoor_login_url(redirect_uri: str, state: str = "state"):
    """Builds the Casdoor OAuth login URL manually."""
    base_url = CASDOOR_ENDPOINT.rstrip("/")
    params = {
        "client_id": CASDOOR_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid",  # Add additional scopes if needed (e.g., "profile email")
        "state": state,
    }
    query_string = urllib.parse.urlencode(params)
    return f"{base_url}/login/oauth/authorize?{query_string}"


def get_casdoor_signup_url(redirect_uri: str, state: str = "state"):
    """Builds the Casdoor OAuth signup URL manually."""
    base_url = CASDOOR_ENDPOINT.rstrip("/")
    params = {
        "client_id": CASDOOR_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid",  # Add additional scopes if needed
        "state": state,
    }
    query_string = urllib.parse.urlencode(params)
    return f"{base_url}/signup/oauth/authorize?{query_string}"


def get_oauth_token(code: str) -> dict:
    """Exchanges the authorization code for an access token."""
    url = f"{CASDOOR_ENDPOINT.rstrip('/')}/api/login/oauth/access_token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": CASDOOR_CLIENT_ID,
        "client_secret": CASDOOR_CLIENT_SECRET,
        "code": code,
    }
    response = requests.post(url, data=payload)
    if response.status_code != 200:
        return {"error": "Failed to obtain token"}
    return response.json()


def parse_jwt_token(token: str) -> dict:
    """Parses and decodes the JWT using the provided certificate."""
    certificate = x509.load_pem_x509_certificate(CASDOOR_CERT.encode("utf-8"), default_backend())
    public_key = certificate.public_key()
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=CASDOOR_CLIENT_ID,
        leeway=80  # allow a 80-second clock skew
    )


def login():
    """Redirects the user to Casdoor's OAuth login URL."""
    # Adjust the redirect URI as needed. In a plugin environment, it should match your registration.
    redirect_uri = "http://localhost:8000/casdoor/callback"
    login_url = get_casdoor_login_url(redirect_uri)
    return redirect(login_url)


def signup():
    """Redirects the user to Casdoor's OAuth signup URL."""
    redirect_uri = "http://localhost:8000/casdoor/callback"
    signup_url = get_casdoor_signup_url(redirect_uri)
    return redirect(signup_url)


def callback():
    """Handles the callback from Casdoor after authentication."""
    code = request.args.get("code")
    if not code:
        return Response("Missing authorization code", status=400)
    
    token_info = get_oauth_token(code)
    if "id_token" not in token_info:
        return Response("Token response missing id_token", status=400)
    
    try:
        user_info = parse_jwt_token(token_info["id_token"])
    except Exception as e:
        return Response(f"Error parsing token: {str(e)}", status=400)
    
    return jsonify({"token_info": token_info, "user": user_info})
