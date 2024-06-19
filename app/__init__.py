from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager
import os

# Load environment variables from .env file
load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()
jwt = JWTManager()

# Initialize Limiter
limiter = Limiter(
    get_remote_address,
    app=None,  # Initialize with the app later
    default_limits=["200 per day", "50 per hour"]
)

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)  # Initialize Limiter with the app

    migrate = Migrate(app, db)

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    @app.after_request
    def set_csrf_cookie(response):
        if 'csrf_token' not in request.cookies:
            response.set_cookie('csrf_token', generate_csrf())
        return response

    @app.before_request
    def disable_csrf_for_api():
        if request.path.startswith('/api/'):
            setattr(request, '_disable_csrf', True)
    
    from app.auth.routes import auth as auth_blueprint
    from app.cms.routes import cms as cms_blueprint
    from app.api.routes import api as api_blueprint
    from app.main.routes import main as main_blueprint
    
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    app.register_blueprint(cms_blueprint, url_prefix='/admin')
    app.register_blueprint(api_blueprint, url_prefix='/api')
    app.register_blueprint(main_blueprint)

    return app
