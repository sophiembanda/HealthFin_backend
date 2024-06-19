import os

class Config:
    SECRET_KEY = 'oukTCBjR5s05jv-B6LoZzeeJnmNVX_ZB'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    JWT_SECRET_KEY = 'oukTCBjR5s05jv-B6LoZzeeJnmNVX_ZB'
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'sammymaiko721@gmail.com'
    MAIL_PASSWORD = 'csof mpai lgqd zqsg'
    MAIL_DEFAULT_SENDER = 'sammymaiko721@gmail.com'
    SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT')
    # MAIL_USERNAME = os.getenv('EMAIL_USER')
    # MAIL_PASSWORD = os.getenv('EMAIL_PASS')
