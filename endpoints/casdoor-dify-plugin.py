import os
import urllib.parse
import requests
import jwt
import json
import logging
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from werkzeug import Request, Response
from dify_plugin import Endpoint
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load environment variables from .env
load_dotenv()

# Retrieve credentials from environment variables
CASDOOR_CERT = os.getenv("CASDOOR_CERT")
CASDOOR_ENDPOINT = os.getenv("CASDOOR_ENDPOINT")
CASDOOR_CLIENT_ID = os.getenv("CASDOOR_CLIENT_ID")
CASDOOR_CLIENT_SECRET = os.getenv("CASDOOR_CLIENT_SECRET")
CASDOOR_ORG_NAME = os.getenv("CASDOOR_ORG_NAME")
CASDOOR_APP_NAME = os.getenv("CASDOOR_APP_NAME")


class CasdoorDifyPluginEndpoint(Endpoint):
    def get_casdoor_login_url(self, redirect_uri: str, state: str = "state") -> str:
        """Builds the Casdoor OAuth login URL."""
        base_url = CASDOOR_ENDPOINT.rstrip("/")
        params = {
            "client_id": CASDOOR_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",  # add more scopes if needed (e.g., "profile email")
            "state": state,
        }
        query_string = urllib.parse.urlencode(params)
        login_url = f"{base_url}/login/oauth/authorize?{query_string}"
        logging.info(f"Constructed login URL: {login_url}")
        return login_url

    def get_casdoor_signup_url(self, redirect_uri: str, state: str = "state") -> str:
        """Builds the Casdoor OAuth signup URL."""
        base_url = CASDOOR_ENDPOINT.rstrip("/")
        params = {
            "client_id": CASDOOR_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",  # add more scopes if needed
            "state": state,
        }
        query_string = urllib.parse.urlencode(params)
        signup_url = f"{base_url}/signup/oauth/authorize?{query_string}"
        logging.info(f"Constructed signup URL: {signup_url}")
        return signup_url

    def get_oauth_token(self, code: str) -> dict:
        """Exchanges the authorization code for an access token."""
        url = f"{CASDOOR_ENDPOINT.rstrip('/')}/api/login/oauth/access_token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": CASDOOR_CLIENT_ID,
            "client_secret": CASDOOR_CLIENT_SECRET,
            "code": code,
        }
        logging.info(f"Requesting token with code: {code} from URL: {url}")
        response = requests.post(url, data=payload)
        if response.status_code != 200:
            logging.error("Failed to obtain token, status code: %s", response.status_code)
            return {"error": "Failed to obtain token"}
        logging.info("Token obtained successfully.")
        return response.json()

    def parse_jwt_token(self, token: str) -> dict:
        """Parses and decodes the JWT using the provided certificate."""
        logging.info("Parsing JWT token.")
        certificate = x509.load_pem_x509_certificate(CASDOOR_CERT.encode("utf-8"), default_backend())
        public_key = certificate.public_key()
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=CASDOOR_CLIENT_ID,
            leeway=80  # allow an 80-second clock skew
        )

    def _invoke(self, r: Request, values: Mapping, settings: Mapping) -> Response:
        """
        Invokes the endpoint based on the action specified in the query parameters.
        Use:
          - ?action=login    for login redirection
          - ?action=signup   for signup redirection
          - ?action=callback to handle the OAuth callback
        """
        action = r.args.get("action", "login")  # Default to login if not provided
        logging.info(f"Received action: {action}")

        # You can pass a custom redirect_uri via settings; otherwise use default.
        redirect_uri = settings.get("redirect_uri", "http://localhost:8000/casdoor/callback")
        logging.info(f"Using redirect URI: {redirect_uri}")

        if action == "login":
            login_url = self.get_casdoor_login_url(redirect_uri)
            logging.info(f"Redirecting to login URL: {login_url}")
            response = Response(status=302)
            response.headers["Location"] = login_url
            return response

        elif action == "signup":
            signup_url = self.get_casdoor_signup_url(redirect_uri)
            logging.info(f"Redirecting to signup URL: {signup_url}")
            response = Response(status=302)
            response.headers["Location"] = signup_url
            return response

        elif action == "callback":
            code = r.args.get("code")
            if not code:
                logging.error("Callback error: Missing authorization code")
                return Response("Missing authorization code", status=400)

            logging.info(f"Received callback with code: {code}")
            token_info = self.get_oauth_token(code)
            if "id_token" not in token_info:
                logging.error("Callback error: Token response missing id_token")
                return Response("Token response missing id_token", status=400)

            try:
                user_info = self.parse_jwt_token(token_info["id_token"])
                logging.info("JWT token parsed successfully.")
            except Exception as e:
                logging.exception("Error parsing token")
                return Response(f"Error parsing token: {str(e)}", status=400)

            data = {"token_info": token_info, "user": user_info}
            logging.info("Callback processed successfully, returning user data.")
            return Response(json.dumps(data), status=200, content_type="application/json")

        else:
            logging.error(f"Invalid action received: {action}")
            return Response("Invalid action", status=400)
