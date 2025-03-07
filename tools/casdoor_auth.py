import os
import urllib.parse
from dotenv import load_dotenv
from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
from casdoor import CasdoorSDK

# Load environment variables from .env file
load_dotenv()

# Retrieve Casdoor configuration from environment variables
CASDOOR_CERT = os.getenv("CASDOOR_CERT")
CASDOOR_ENDPOINT = os.getenv("CASDOOR_ENDPOINT")
CASDOOR_CLIENT_ID = os.getenv("CASDOOR_CLIENT_ID")
CASDOOR_CLIENT_SECRET = os.getenv("CASDOOR_CLIENT_SECRET")
CASDOOR_ORG_NAME = os.getenv("CASDOOR_ORG_NAME")
CASDOOR_APP_NAME = os.getenv("CASDOOR_APP_NAME")


class CasdoorAuthTool(Tool):
    def _invoke(self, tool_parameters: dict) -> ToolInvokeMessage:
        action = tool_parameters.get("action")
        
        # Retrieve runtime credentials from the provider config, if available.
        # Fallback to environment values if not provided at runtime.
        credentials = self.runtime.credentials
        client_id = credentials.get("casdoor_client_id", CASDOOR_CLIENT_ID)
        client_secret = credentials.get("casdoor_client_secret", CASDOOR_CLIENT_SECRET)
        
        # Use environment variables for endpoint, organization, and application name.
        endpoint = os.getenv("CASDOOR_ENDPOINT", CASDOOR_ENDPOINT)
        org_name = os.getenv("CASDOOR_ORG_NAME", CASDOOR_ORG_NAME)
        application_name = os.getenv("CASDOOR_APP_NAME", CASDOOR_APP_NAME)
        
        # Initialize a CasdoorSDK instance with the provided credentials.
        casdoor_sdk = CasdoorSDK(
            endpoint=endpoint,
            client_id=client_id,
            client_secret=client_secret,
            certificate=CASDOOR_CERT,
            org_name=org_name,
            application_name=application_name
        )
        
        # Use a runtime custom value for redirect_uri if provided, or default.
        redirect_uri = self.runtime.custom.get("redirect_uri", "http://localhost:8000/callback")
        
        # Generate the proper URL based on the action.
        base_url = casdoor_sdk.endpoint.rstrip("/")
        params = {
            "client_id": casdoor_sdk.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",
            "state": "state"
        }
        query_string = urllib.parse.urlencode(params)
        
        if action == "login":
            url = f"{base_url}/login/oauth/authorize?{query_string}"
        elif action == "signup":
            url = f"{base_url}/signup/oauth/authorize?{query_string}"
        else:
            url = "Invalid action. Please use 'login' or 'signup'."
        
        return self.create_text_message(url)
