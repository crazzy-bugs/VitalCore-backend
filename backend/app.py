from flask import Flask
from src.scans import scans_bp
from src.notifications import notifications_bp
from src.antivirus import antivirus_bp
from src.settings import settings_bp
from src.target import target_bp
from database import init_db

app = Flask(__name__)

# Initialize the database
init_db()

# Register blueprints
app.register_blueprint(scans_bp, url_prefix='/scans')
app.register_blueprint(notifications_bp, url_prefix='/notifications')
app.register_blueprint(antivirus_bp, url_prefix='/antiviruses')
app.register_blueprint(settings_bp, url_prefix='/settings')
app.register_blueprint(target_bp, url_prefix='/target')

if __name__ == '__main__':
    app.run(debug=True, port=3000)
