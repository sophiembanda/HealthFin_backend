from flask_mail import Message
from app import mail
from flask import url_for

# def send_email(subject, recipient, body):
#     msg = Message(subject, recipients=[recipient])
#     msg.body = body
#     mail.send(msg)

def send_email(subject, recipients, body_template, **kwargs):
    msg = Message(subject, sender='noreply@example.com', recipients=recipients)
    msg.body = body_template.format(**kwargs)
    try:
        mail.send(msg)
        print(f'Email sent to {recipients} with subject: {subject}')
    except Exception as e:
        print(f'Failed to send email: {str(e)}')

def send_login_alert_email(user_email, token):
    block_url = url_for('auth.block_account', token=token, _external=True)
    msg = Message('Login Alert', sender='noreply@example.com', recipients=[user_email])
    msg.body = f'Your account was logged in. If it was not you, click the link to block the account: {block_url}'
    try:
        mail.send(msg)
        print(f'Login alert email sent to {user_email}')
    except Exception as e:
        print(f'Failed to send login alert email: {str(e)}')

        
def send_block_account_email(user_email):
    msg = Message('Account Blocked', sender='noreply@example.com', recipients=[user_email])
    msg.body = 'Your account has been blocked due to suspicious activity.'
    try:
        mail.send(msg)
        print(f'Account blocked email sent to {user_email}')
    except Exception as e:
        print(f'Failed to send account blocked email: {str(e)}')

def send_password_reset_email(user_email, token):
    reset_url = url_for('auth.password_reset_get', token=token, _external=True)
    msg = Message('Password Reset Request', sender='noreply@example.com', recipients=[user_email])
    msg.body = f'To reset your password, visit the following link: {reset_url}'
    try:
        mail.send(msg)
        print(f'Password reset email sent to {user_email} with token: {token}')
    except Exception as e:
        print(f'Failed to send password reset email: {str(e)}')
