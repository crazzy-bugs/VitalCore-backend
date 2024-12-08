from flask import Blueprint

antivirus_bp = Blueprint('antivirus', __name__, url_prefix='/antivirus')

from . import routes