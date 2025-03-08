# Casdoor Dify Plugin

## Overview
The Casdoor Dify Plugin integrates Casdoor OAuth-based authentication into the Dify ecosystem as an extension plugin. It provides endpoints to handle OAuth login, signup, and callback flows, enabling seamless user authentication via Casdoor.

## Features
- **OAuth Authentication:**  
  Implements login, signup, and callback endpoints to facilitate the Casdoor OAuth flow.
- **Dify Plugin Integration:**  
  Uses a plugin manifest and endpoint YAML definitions to register the plugin with Dify.
- **Environment-Based Configuration:**  
  Loads sensitive credentials (certificates, client IDs, secrets, etc.) from a `.env` file.
- **Local Testing with Flask:**  
  Includes a Flask-based server (`main.py`) for local development and testing.

## Project Structure
```
.
├── GUIDE.md                   # Quick start guide for plugin development
├── README.md                  # Project documentation
├── _assets
│   └── icon.svg               # Plugin icon asset
├── endpoints
│   ├── casdoor_auth.py         # Casdoor OAuth logic implementation
│   ├── casdoor_login.yaml      # Endpoint manifest for login
│   ├── casdoor_signup.yaml     # Endpoint manifest for signup
│   └── casdoor_callback.yaml   # Endpoint manifest for callback
├── main.py                    # Entry point for local testing (Flask server)
├── manifest.yaml              # Plugin manifest for Dify integration
└── requirements.txt           # Python dependencies list
```

## Prerequisites
- **Python:** Version 3.12 or higher.
- **Poetry:** For dependency management. ([Installation Guide](https://python-poetry.org/docs/))
- **Dify Plugin Scaffolding Tool:** (Optional) For further development and testing on the Dify platform.
- **Environment Variables:** A `.env` file containing your Casdoor credentials is required.

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
CASDOOR_ENDPOINT=https://your-casdoor-endpoint.example
CASDOOR_CLIENT_ID=your_client_id
CASDOOR_CLIENT_SECRET=your_client_secret
CASDOOR_ORG_NAME=your_organization_name
CASDOOR_APP_NAME=your_app_name
```

## Running the Plugin Locally
For local testing, run the Flask server with:
```bash
poetry run python main.py
```
This starts the server on `http://0.0.0.0:8000`.

## Testing the Endpoints
- **Login Endpoint:**  
  Navigate to [http://localhost:8000/casdoor/login](http://localhost:8000/casdoor/login) to initiate the Casdoor OAuth login flow.
- **Signup Endpoint:**  
  Visit [http://localhost:8000/casdoor/signup](http://localhost:8000/casdoor/signup) to start the signup process.
- **Callback Endpoint:**  
  After authentication, Casdoor redirects to [http://localhost:8000/casdoor/callback](http://localhost:8000/casdoor/callback). This endpoint exchanges the authorization code for tokens and parses the JWT.

## Dify Plugin Integration
This repository is structured as a Dify extension plugin:
- **Manifest File (`manifest.yaml`):**  
  Contains metadata and required permissions for plugin registration with Dify.
- **Endpoint YAML Files (in `endpoints/`):**  
  Define the API paths and HTTP methods for login, signup, and callback endpoints.

For more details on developing and integrating plugins with Dify, please refer to the [Dify Plugin Documentation](https://docs.dify.ai/plugins/quick-start/develop-plugins/extension-plugin).

## Contributing
Contributions are welcome! Fork the repository and submit pull requests for any improvements. For significant changes, please open an issue to discuss your ideas first.

## License
This project is licensed under the [MIT License](LICENSE).

## Contact
For questions or support, please contact [Mohammad Fotouhi](mailto:mohammad.fotouhi80@gmail.com).
