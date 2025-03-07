from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError
from tools.casdoor_auth import CasdoorAuthTool


class CasdoorProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict) -> None:
        try:
            # Basic validation: ensure both client ID and secret are provided.
            if not credentials.get("casdoor_client_id") or not credentials.get("casdoor_client_secret"):
                raise ValueError("Missing Casdoor client credentials")
            # Optionally, test by generating a login URL.
            _ = CasdoorAuthTool.from_credentials(credentials).invoke(
                tool_parameters={"action": "login"}
            )
        except Exception as e:
            raise ToolProviderCredentialValidationError(str(e))
