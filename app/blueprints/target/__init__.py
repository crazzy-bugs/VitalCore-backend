from flask import Blueprint

target_bp = Blueprint('target', __name__, url_prefix='/target')

from . import routes