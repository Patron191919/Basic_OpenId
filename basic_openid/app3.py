import os
import requests
from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
import jwt
from authlib.jose import JsonWebToken

app = Flask(__name__)
app.secret_key = os.urandom(24)

# OAuth ayarları
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id="806262418089-o2rqvr1uggg1ihvcjj27fm5nkteclid2.apps.googleusercontent.com",
    client_secret="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",
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs', 
   
)

@app.route('/')
def home():
    if 'user_info' in session:
        user_info = session['user_info']
        return f"Merhaba, {user_info['name']}! Şu an site3'desiniz, iyi günler."
    else:
        return redirect(url_for('login'))

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/callback')
def authorize():
    token = google.authorize_access_token()
    
    # Token'daki id_token'ı çöz ve 'iss' claim'ini kontrol et
    id_token = token.get('id_token')
    if id_token:
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        print("Decoded ID Token:", decoded_token)
        print("Issuer (iss):", decoded_token.get('iss'))  # Burada 'iss' claim'ini göreceksiniz
    
    user_info = google.get('userinfo').json()
    session['user_info'] = user_info
    return redirect('/')

if __name__ == '__main__':
    app.run(port=5003, debug=True)
