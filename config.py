from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'fetch.login_post'

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Ln3486160@localhost:5432/rpp_6'
app.config['SQLAlchemy_TRACK_MODIFIVATTION'] = False
