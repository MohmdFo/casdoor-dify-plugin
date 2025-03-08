from flask import Flask
from endpoints import casdoor_auth

app = Flask(__name__)

# Register endpoints
app.add_url_rule("/casdoor/login", view_func=casdoor_auth.login)
app.add_url_rule("/casdoor/signup", view_func=casdoor_auth.signup)
app.add_url_rule("/casdoor/callback", view_func=casdoor_auth.callback)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
