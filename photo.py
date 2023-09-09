from flask import Flask, request, render_template, redirect, url_for, jsonify, make_response, send_from_directory
import os 
from flask_restful import Resource, Api
from werkzeug.utils import secure_filename
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_limiter import Limiter

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a strong secret key
app.config['RATELIMIT_DEFAULT'] = '5 per minute'  # Rate limit for API calls (5 requests per minute)

# Initialize the API and rate limiter
api = Api(app)
limiter = Limiter(app)

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401

    return decorator

# Simple HTML interface
@app.route('/')
def home():
    return render_template('home.html')

# Upload page to submit images
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['image']
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('image', filename=filename))
    return "No file uploaded."

# Page to display the uploaded image
@app.route('/image/<filename>')
def image(filename):
    return render_template('image.html', filename=filename)

# Login to generate a JWT token
@app.route('/login')
def login():
    auth = request.authorization
    if auth and auth.password == 'password':
        token = jwt.encode({
            'user': auth.username,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

# API endpoint protected by token and rate limit
class ProtectedResource(Resource):
    @token_required
    @limiter.limit(app.config['RATELIMIT_DEFAULT'])
    def get(self):
        return "You have accessed the protected API"

api.add_resource(ProtectedResource, '/api')

# Serve uploaded images
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
