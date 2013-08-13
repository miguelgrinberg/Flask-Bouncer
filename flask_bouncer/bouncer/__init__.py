from flask import Blueprint

blueprint = Blueprint('bouncer', __name__, template_folder = 'templates', static_folder = 'static')

from . import views

