from flask import Blueprint
routes = Blueprint('routes', __name__)

from .gsb import *
from .docoska import *
from .whoip import *
