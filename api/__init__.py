from flask import Flask, Blueprint
from flask_restful import Api

from config import config


def create_app(env):
    app = Flask(__name__)
    app.config.from_object(config[env])
    api_bp = Blueprint('api', __name__)
    api = Api(api_bp)

    # Code for adding Flask RESTful resources goes here
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    
    return app