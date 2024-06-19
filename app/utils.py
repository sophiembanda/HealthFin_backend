import email_validator
from flask_mail import Message
from app import mail
import re
from flask import current_app, json, request, jsonify
from functools import wraps
from itsdangerous import BadSignature, Serializer, SignatureExpired
from .models import BlacklistToken, User
import jwt
import datetime
from email_validator import validate_email as email_validator, EmailNotValidError

def send_email(subject, recipients, template, **kwargs):
    msg = Message(subject, recipients=recipients)
    msg.body = template
    mail.send(msg)

def validate_email(email):
    try:
        email_validator(email)
        return True
    except EmailNotValidError:
        return False
    
def validate_input(email_or_phone, password):
    email_regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$'
    phone_regex = r'^\+254\d{9}$'
    local_phone_regex = r'^07\d{8}$'
    
    if not email_or_phone or not password:
        return False, 'Email or phone number and password are required.'

    if re.match(email_regex, email_or_phone):
        return True, 'Valid email format.'
    
    if re.match(phone_regex, email_or_phone):
        return True, 'Valid phone number format.'

    if re.match(local_phone_regex, email_or_phone):
        return True, f'Phone number formatted to international: +254{email_or_phone[1:]}'

    return False, 'Invalid email or phone number format.'

def generate_token(user_id):
    token = jwt.encode(
        {
            'user_id': user_id,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        },
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return token

# def generate_token(user_id, expiration=3600):
#     s = Serializer(current_app.config['SECRET_KEY'])
#     return s.dumps(user_id, salt=current_app.config['SECURITY_PASSWORD_SALT'])

def verify_token(token):
    try:
        # Print the SECRET_KEY to ensure it's correct
        print(f"SECRET_KEY: {current_app.config['SECRET_KEY']}")

        # Decode the token using the JWT library
        decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']
        return user_id
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return None
    
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization'].split()
            if len(auth_header) == 2 and auth_header[0] == "Bearer":
                token = auth_header[1]

        # print(f"Token received: {token}") 
        # token = request.headers.get('x-access-tokens')
        if not token:
            return jsonify({'error': 'Token is missing'}), 403

        if BlacklistToken.check_blacklist(token):
            return jsonify({'error': 'Token is blacklisted'}), 401


        try:
            # data = jwt.decode(token, 'SECRET_KEY', algorithms=['HS256'])
            decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            token_json = json.loads(json.dumps(decoded_token))
            # current_user = User.query.filter_by(id=data['user_id']).first()
            current_user = User.query.filter_by(id=token_json['user_id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

def validate_amount(amount):
    try:
        value = float(amount)
        return value > 0
    except ValueError:
        return False

def validate_phone_number(phone_number):
    return re.match(r"^(\+254|0)?7\d{8}$", phone_number) is not None

def validate_required_fields(data, required_fields):
    errors = []
    for field in required_fields:
        if not data.get(field):
            errors.append(f"Missing required field: {field}")
    return errors

def validate_contact_form(data):
    errors = []
    
    name = data.get('name')
    if not name or len(name) > 50:
        errors.append("Invalid name")
    
    email = data.get('email')
    try:
        validate_email(email)
    except EmailNotValidError:
        errors.append("Invalid email")
    
    message = data.get('message')
    if not message or len(message) > 1000:
        errors.append("Invalid message")
    
    return errors