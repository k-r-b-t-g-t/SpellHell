from flask import Flask
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from passlib.handlers.pbkdf2 import pbkdf2_sha512

# Configure app
app = Flask(__name__)
app.secret_key = 'This is one super secret key!'

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/spellhell.sqlite3'
db = SQLAlchemy(app)


class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(32), nullable=False)
    telephone = db.Column(db.String(10), nullable=False)
    admin = db.Column(db.String(1), nullable=False)

class Queries(db.Model):
    __tablename__ = "queries"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.Integer, nullable=False)
    time = db.Column(db.String(100), nullable=False)
    querytext = db.Column(db.String(10000), nullable=False)
    queryresults = db.Column(db.String(10000), nullable=False)

class Authentication(db.Model):
    __tablename__ = "history"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(6), nullable=False)
    time = db.Column(db.String(100), nullable=False)

