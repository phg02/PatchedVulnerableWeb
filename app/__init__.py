from flask import Flask
from flask_cors import CORS
from config import config
import os
from werkzeug.proxy_fix import ProxyFix

def create_app(config_name=None):
    """Application factory"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config.get(config_name, config['default']))
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Session configuration
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 3600
    
    # Configure upload folder
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'uploads')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    
    # CORS configuration
    CORS(app, resources={r"/*": {"origins": ["*"]}}, supports_credentials=True)
    
    # Basic security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        return response
    
    # Register database functions
    from app.database import close_db, init_db
    app.teardown_appcontext(close_db)
    
    # Register commands
    @app.cli.command()
    def init_db_command():
        """Initialize the database"""
        from app.database import init_db, get_db
        get_db()
        init_db()
        print("Initialized the database")
    
    # Register blueprints
    from app.routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    
    return app
