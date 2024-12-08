from flask import Flask
# from src.scans import scans_bp
# from src.notifications import notifications_bp
# from src.antivirus import antivirus_bp
# from src.settings import settings_bp
from .blueprints.target import target_bp
from .blueprints.antivirus import antivirus_bp
from .database import init_db

def create_app():
    app = Flask(__name__)
    # app.config.from_object('app.config.Config')
# Initialize the database
    init_db()
    app.register_blueprint(target_bp, url_prefix='/target')
    app.register_blueprint(antivirus_bp, url_prefix='/antivirus')
    
# Register blueprints
# app.register_blueprint(scans_bp, url_prefix='/scans')
# app.register_blueprint(notifications_bp, url_prefix='/notifications')
# app.register_blueprint(antivirus_bp, url_prefix='/antiviruses')
# app.register_blueprint(settings_bp, url_prefix='/settings')

    return app
