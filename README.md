# Casdoor Dify Plugin

## Overview
This package integrates Casdoor OAuth-based authentication into a Dify plugin, enabling seamless user authentication within the Dify ecosystem. The project leverages FastAPI for handling OAuth endpoints and uses a set of provider and tool manifest files to register the plugin with Dify.

## Features
- **OAuth Authentication:** Implements login, signup, and callback endpoints for Casdoor-based authentication.
- **Dify Plugin Integration:** Provides Dify provider and tool manifests, along with corresponding Python code for integration.
- **Configuration via Environment Variables:** Loads sensitive data (certificates, client IDs, secrets, etc.) from a `.env` file.
- **Dependency Management:** Uses Poetry for managing dependencies and virtual environments.
- **Customizable Assets:** Includes a plugin icon for visual identification in the Dify interface.

## Project Structure
```
casdoor-dify-plugin/
├── assets/
│   └── icon.png                # Plugin icon asset
├── main.py                     # FastAPI application for local testing
├── .env                        # Environment configuration file
├── poetry.lock                 # Poetry lock file for dependency management
├── pyproject.toml              # Poetry project configuration
├── provider/
│   ├── __init__.py             # Provider package initialization
│   ├── casdoor.yaml            # Provider manifest for Dify integration
│   └── casdoor_plugin.py       # Provider code for credential validation
├── tools/
│   ├── __init__.py             # Tools package initialization
│   ├── casdoor_auth.py         # Tool implementation for generating OAuth URLs
│   └── casdoor_auth.yaml       # Tool manifest for Dify integration
└── README.md                   # Project documentation
```

## Prerequisites
- **Python:** Version 3.12 or higher.
- **Poetry:** For dependency management. ([Installation Guide](https://python-poetry.org/docs/))
- **python-dotenv:** For loading environment variables. Install with `pip install python-dotenv`.
- **Dify Plugin Scaffolding Tool:** (Optional) To further develop and test your Dify plugin.

## Installation
1. **Clone the Repository:**
   ```bash
   git clone <repository-url>
   cd casdoor-dify-plugin
   ```
2. **Install Dependencies:**
   ```bash
   poetry install
   ```

## Configuration
Create a `.env` file in the project root and populate it with your Casdoor credentials:
```env
CASDOOR_CERT="-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----"
CASDOOR_ENDPOINT=https://yourendpoint.example/
CASDOOR_CLIENT_ID=your_client_id
CASDOOR_CLIENT_SECRET=your_client_secret
CASDOOR_ORG_NAME=your-organization-name
CASDOOR_APP_NAME=your-app-name
```

## Running the Application
To run the FastAPI application locally for testing, execute:
```bash
poetry run uvicorn main:app --reload
```
Access the following endpoints in your browser:
- **/login:** Initiates the OAuth login flow.
- **/signup:** Initiates the OAuth signup flow.
- **/callback:** Handles the OAuth callback and token exchange.

## Dify Plugin Integration
This repository also contains the necessary manifests and code to integrate the Casdoor authentication as a Dify plugin:
- **Provider Integration:**  
  - `provider/casdoor.yaml`: Defines provider metadata, credentials, and tool references.  
  - `provider/casdoor_plugin.py`: Implements credential validation and provider logic.
- **Tool Integration:**  
  - `tools/casdoor_auth.yaml`: Specifies tool identity, description, and parameters.  
  - `tools/casdoor_auth.py`: Contains the tool logic to generate OAuth URLs based on provided actions.

For further integration details and registration with Dify, please refer to the [Dify Plugin Documentation](https://docs.dify.ai/plugins/quick-start/develop-plugins/tool-plugin).

## Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes. For major changes, open an issue first to discuss your ideas.

## License
This project is licensed under the [MIT License](LICENSE).

## Contact
For questions or support, please contact [Mohammad Fotouhi](mailto:your.mohammad.fotouhi80@gmail.com).
