import datetime
from flask import Blueprint, logging, render_template, request, jsonify, session, url_for, current_app
from flask_login import login_user, logout_user, login_required, current_user
from itsdangerous import BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, mail
from app.auth.forms import RequestPasswordResetForm, ResetPasswordForm, SignupForm
from flask_wtf.csrf import generate_csrf
from app.models import BlacklistToken, User, EmailVerificationToken, PasswordResetToken
from app.utils import send_email
import re
import logging
from app.utils import token_required, generate_token, validate_input, verify_token
from app.email import send_email, send_login_alert_email, send_block_account_email, send_password_reset_email


auth = Blueprint('auth', __name__)

# Validation functions
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def is_valid_kenyan_phone_number(phone_number):
    regex = r'^(?:\+254|0)?[7]\d{8}$'
    return re.match(regex, phone_number) is not None

def is_valid_password(password):
    # At least 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character
    regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(regex, password) is not None
@auth.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    form = SignupForm(data=data)

    if not form.validate():
        return jsonify({'errors': form.errors}), 400

    email = data.get('email')
    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400

    email = data.get('email')
    if not is_valid_email(email):
        print(f"Invalid email format: {email}")
        return jsonify({'error': 'Invalid email format'}), 400
    
    phone_number = data.get('phone_number')
    if not is_valid_kenyan_phone_number(phone_number):
        print(f"Invalid Kenyan phone number: {phone_number}")
        return jsonify({'error': 'Invalid Kenyan phone number'}), 400

    password = data.get('password')
    confirm_password = data.get('confirm_password')
    if not is_valid_password(password):
        print(f"Password does not meet strength requirements: {password}")
        return jsonify({'error': 'Password does not meet strength requirements'}), 400

    if password != confirm_password:
        print("Passwords do not match")
        return jsonify({'error': 'Passwords do not match'}), 400
    hashed_password = generate_password_hash(password, method='sha256')
    user = User(first_name=data.get('first_name'), 
                last_name=data.get('last_name'),
                phone_number=phone_number, 
                email=email
                )
    user.set_password(password) 

    db.session.add(user)
    db.session.commit()

    token = EmailVerificationToken.generate_token(user.id)
    logging.debug(f"Generated token for email verification: {token}")  # Log the token

    verify_url = url_for('auth.verify_email', token=token, _external=True)
    send_email('Verify Your Email Address', [email], 'email/verify', verify_url=verify_url)

    return jsonify({
        'message': 'User created successfully. Please check your email to verify your account.',
        'token': token
    }), 201

@auth.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email_or_phone = data.get('email_or_phone')
    password = data.get('password')

    valid, message = validate_input(email_or_phone, password)
    if not valid:
        return jsonify({'error': message}), 400

    user = User.query.filter((User.email == email_or_phone) | (User.phone_number == email_or_phone)).first()

    if user and user.check_password(password):
        token = generate_token(user.id)
        print(f"Generated Token: {token}")
        # send_email('Login Alert', [user.email], 'Your account was logged in. If it was not you, click the link to block the account.')
        send_login_alert_email(user.email, token)
        return jsonify({'token': token}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    login_user(user)
    return jsonify({'message': 'Login successful'}), 200

# @auth.route('/logout', methods=['GET'])
# @login_required
# def logout():
#     try:
#         logout_user()
#         return jsonify({'message': 'Logged out successfully'}), 200
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# @auth.route('/verify-email/<token>', methods=['GET'])
# def verify_email(token):
#     logging.debug(f"Received token for verification: {token}")  # Log the received token
#     try:
#         user_id = EmailVerificationToken.verify_token(token)
#         logging.debug(f"Token corresponds to user ID: {user_id}")  # Log the user ID from the token
#     except (SignatureExpired, BadSignature) as e:
#         logging.error(f"Token verification failed: {e}")  # Log the error
#         return jsonify({'error': 'Invalid or expired token'}), 400

#     user = User.query.get(user_id)
#     if not user:
#         logging.error("User not found for the given token")  # Log user not found error
#         return jsonify({'error': 'User not found'}), 404

#     user.email_verified = True
#     db.session.commit()

#     return jsonify({'message': 'Email verified successfully'}), 200


@auth.route('/resend-verification', methods=['POST'])
def resend_verification():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.email_verified:
        return jsonify({'message': 'Email already verified'}), 200

    token = EmailVerificationToken.generate_token(user.id)
    logging.debug(f"Generated token for email verification: {token}")  # Log the token

    verify_url = url_for('auth.verify_email', token=token, _external=True)
    send_email('Verify Your Email Address', [email], 'email/verify', verify_url=verify_url)

    return jsonify({'message': 'Verification email sent'}), 200


@auth.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    form = RequestPasswordResetForm(data=data)

    if not form.validate():
        return jsonify({'errors': form.errors}), 400

    user = User.query.filter_by(email=form.email.data).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    token = PasswordResetToken.generate_token(user.id)
    reset_url = url_for('auth.reset_password', token=token, _external=True)
    send_email('Reset Your Password', [form.email.data], 'email/reset_password', reset_url=reset_url)

    return jsonify({
        'message': 'Password reset email sent',
        'token': token
        }), 200

@auth.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    form = ResetPasswordForm(data=data)

    if not form.validate():
        return jsonify({'errors': form.errors}), 400

    user_id = PasswordResetToken.verify_token(token)
    user = User.query.get(user_id)

    hashed_password = generate_password_hash(form.password.data, method='sha256')
    user.password = hashed_password
    db.session.commit()

    return jsonify({'message': 'Password reset successfully'}), 200

@auth.route('/validate', methods=['POST'])
def validate():
    data = request.get_json()
    email_or_phone = data.get('email_or_phone')
    password = data.get('password')

    valid, message = validate_input(email_or_phone, password)
    if not valid:
        return jsonify({'error': message}), 400

    return jsonify({'message': message}), 200

@auth.route('/refresh-token', methods=['POST'])
@token_required
def refresh_token(current_user):
    token = generate_token(current_user.id)
    return jsonify({'token': token}), 200

@auth.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    # Blacklist the current token
    auth_header = request.headers['Authorization']
    token = auth_header.split()[1]
    blacklist_token = BlacklistToken(token=token)
    try:
        db.session.add(blacklist_token)
        db.session.commit()
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@auth.route('/password-reset-request', methods=['POST'])
def password_reset_request():
    data = request.get_json()
    email_or_phone = data.get('email_or_phone')

    user = User.query.filter((User.email == email_or_phone) | (User.phone_number == email_or_phone)).first()
    if user:
        token = generate_token(user.id)
        # reset_url = url_for('auth.password_reset', token=token, _external=True)
        # email_body = f'To reset your password, visit the following link: {reset_url}'
        # send_email('Password Reset Request', [user.email], email_body)
        send_password_reset_email(user.email, token)
        return jsonify({'message': 'Password reset link sent'}), 200
    return jsonify({'error': 'User not found'}), 404

@auth.route('/password-reset', methods=['POST'])
def password_reset():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
        
    if not data:
        print("No JSON body received")
        return jsonify({'error': 'Invalid request, JSON body required'}), 400
    
    token = data.get('token')
    new_password = data.get('new_password')
    print(f"Token received for password reset: {token}")  # Debug print statement
    print(f"New password received for password reset: {new_password}")  # Debug print statement

    
    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400


    user_id = verify_token(token)
    if user_id is None:
        return jsonify({'error': 'Invalid or expired token'}), 400

    user = User.query.get(user_id)
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'message': 'Password reset successful'}), 200

    return jsonify({'error': 'User not found'}), 404

@auth.route('/password-reset', methods=['GET'])
def password_reset_get():
    token = request.args.get('token')
    return render_template('password_reset_form.html', token=token)

@auth.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    user_id = verify_token(token)
    if user_id is None:
        return jsonify({'error': 'Invalid or expired token'}), 400

    user = User.query.get(user_id)
    if user:
        user.email_verified = True
        db.session.commit()
        return jsonify({'message': 'Email verified successfully'}), 200

    return jsonify({'error': 'User not found'}), 404

@auth.route('/session-status', methods=['GET'])
@token_required
def session_status(current_user):
    # Update last login timestamp
    current_user.last_login = datetime.datetime.now()
    db.session.commit()

    # Additional session information
    session_info = {
        'id': current_user.id,
        'email': current_user.email,
        'phone': current_user.phone,
        'email_verified': current_user.email_verified,
        'is_blocked': current_user.is_blocked,
        'last_login': current_user.last_login.strftime('%Y-%m-%d %H:%M:%S') if current_user.last_login else None,
        'session_start_time': current_user.session_start_time.strftime('%Y-%m-%d %H:%M:%S') if current_user.session_start_time else None,
        'ip_address': request.remote_addr
    }

    # Determine if session has expired based on your business logic
    if current_user.session_start_time:
        session_expiry_time = current_user.session_start_time + datetime.timedelta(hours=2)  # Example: Session expires in 2 hours
        if datetime.datetime.now() > session_expiry_time:
            session_info['session_expired'] = True
        else:
            session_info['session_expired'] = False
    else:
        session_info['session_expired'] = True  # No session start time means session is considered expired

    return jsonify(session_info), 200


@auth.route('/block-account', methods=['POST'])
def block_account():
    data = request.get_json()
    token = data.get('token')
    print(f"Token received for block account: {token}")  # Debug print statement

    user_id = verify_token(token)
    if user_id is None:
        print("Invalid or expired token")  # Debug print statement
        return jsonify({'error': 'Invalid or expired token'}), 400

    user = User.query.get(user_id)
    if user:
        user.is_blocked = True
        db.session.commit()
        print(f"User {user.email} blocked successfully")  # Debug print statement
        return jsonify({'message': 'Account blocked successfully'}), 200

    print("User not found")  # Debug print statement
    return jsonify({'error': 'User not found'}), 404

@auth.route('/check-account-status', methods=['POST'])
@token_required
def check_account_status(current_user):
    return jsonify({
        'email': current_user.email,
        'is_blocked': current_user.is_blocked
    }), 200


@auth.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token}), 200
