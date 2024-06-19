from datetime import datetime
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from app import db, login_manager

class User(db.Model, UserMixin):
    # __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64), index=True)
    last_name = db.Column(db.String(64), index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    phone_number = db.Column(db.String(20), unique=True)
    password_hash = db.Column(db.String(128))
    email_verified = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    session_start_time = db.Column(db.DateTime)
    loan_applications = db.relationship('LoanApplication', backref='user', lazy=True)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)


    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # def __init__(self, first_name, last_name, email, phone_number,password, 
    #              email_verified=False, is_blocked=False, created_at=None, last_login=None, session_start_time=None):
    #     self.first_name = first_name
    #     self.last_name = last_name
    #     self.email = email
    #     self.phone_number = phone_number
    #     self.email_verified = email_verified
    #     self.password_hash = password
    #     self.is_blocked = is_blocked
    #     if created_at:
    #         self.created_at = created_at
    #     if last_login:
    #         self.last_login = last_login
    #     if session_start_time:
    #         self.session_start_time = session_start_time

    def __repr__(self):
        return f'<User {self.email}>'
    
    def get_id(self):
        return str(self.id)
    
    def start_session(self):
        self.session_start_time = datetime.now()
        db.session.commit()

    def end_session(self):
        self.session_start_time = None
        db.session.commit()

    @staticmethod
    def generate_verification_token(user_id):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps(user_id, salt=current_app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def verify_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'])
        except:
            return None
        return user_id

class ContactForm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    email = db.Column(db.String(120))
    message = db.Column(db.String(256))
    
class BlacklistToken(db.Model):
    # __tablename__ = 'blacklist_tokens'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.utcnow()

    def __repr__(self):
        return f'<BlacklistToken token={self.token}>'

    @staticmethod
    def check_blacklist(auth_token):
        res = BlacklistToken.query.filter_by(token=auth_token).first()
        if res:
            return True
        else:
            return False
        
class EmailVerificationToken(db.Model):
    # __tablename__ = 'email_verification_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(120), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref=db.backref('email_verification_tokens', lazy=True))

    @staticmethod
    def generate_token(user_id):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps(user_id, salt=current_app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def verify_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'])
        except:
            return None
        return user_id


class PasswordResetToken(db.Model):
    # __tablename__ = 'password_reset_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(120), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def generate_token(user_id):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps(user_id, salt=current_app.config['SECURITY_PASSWORD_SALT'])

    @staticmethod
    def verify_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'])
        except:
            return None
        return user_id

class ContactFormSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

class HeroContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    subtitle = db.Column(db.String(255), nullable=False)

    def serialize(self):
        return {
            'title': self.title,
            'subtitle': self.subtitle
        }

class FeatureCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)

    def serialize(self):
        return {
            'title': self.title,
            'description': self.description
        }

class AboutContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

    def serialize(self):
        return {
            'content': self.content
        }

class MedicalLoanContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

    def serialize(self):
        return {
            'content': self.content
        }
    
class Testimonial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    feedback = db.Column(db.Text, nullable=False)

    def serialize(self):
        return {
            'name': self.name,
            'feedback': self.feedback
        }

class Savings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Float, nullable=False, default=0.0)

class SavingPlan(db.Model):
    __tablename__ = 'saving_plans'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class LoanApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    required_treatment = db.Column(db.Text, nullable=False)
    estimated_cost = db.Column(db.Float, nullable=False)
    healthcare_provider = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    status = db.Column(db.String(50), nullable=False, default="Pending")

class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.now())  # New field
