from flask_wtf import FlaskForm
from passlib.handlers.pbkdf2 import pbkdf2_sha512
from werkzeug.utils import escape
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, NumberRange, Length, Regexp, EqualTo, ValidationError

from models import *

def check_login(form, field):
    username = escape(form.username.data)
    token = escape(form.telephone.data)
    password = escape(form.password.data)
    user_object = Users.query.filter_by(username=username).first()
    
    if user_object is None:
        raise ValidationError()
    elif token != user_object.telephone:
        raise ValidationError()
    elif not pbkdf2_sha512.verify(password, user_object.password):
        raise ValidationError()

def check_user_id_history(form, field):
    user_id = escape(form.user_id.data)
    history_object = Authentication.query.filter_by(user_id=user_id).all()
    if not history_object:
        print("naww exist")
        raise ValidationError("No history found for User ID.")
        
def check_user_name_history(form, field):
    user_name = escape(form.user_name.data)
    history_object = Queries.query.filter_by(user_name=user_name).all()
    if not history_object:
        print("naww exist")
        raise ValidationError("No history found for User ID.")

def check_duplicate_user(form, field):
    username = escape(form.username.data)
    user_object = Users.query.filter_by(username=username).first()
    if user_object:
        raise ValidationError("Username already taken.")

class QueryHistoryForm(FlaskForm):
    user_name = StringField('username_label', validators=[InputRequired(message="User Name cannot be blank."), Length(min=1, max=10, message="User Name must be between 1 and 25 characters in length.")], id="user_name")
    submit_button = SubmitField('Search', validators=[check_user_name_history])
    
class AuthHistoryForm(FlaskForm):
    user_id = StringField('username_label', validators=[InputRequired(message="User ID cannot be blank."), Length(min=1, max=10, message="User ID must be between 1 and 10 characters in length.")], id="user_id")
    submit_button = SubmitField('Search', validators=[check_user_id_history])

class RegistrationForm(FlaskForm):
    username = StringField('username_label', validators=[InputRequired(message="Username cannot be blank."), Length(min=5, max=20, message="Username must be between 5 and 20 characters in length.")], id="uname")
    telephone = StringField('telephone_label', validators=[InputRequired(message="Telephone cannot be blank."), Length(min=11, max=11, message="Telephone must be exactly 11 characters."), Regexp('[0-9]{10}', message="Telephone must contain only digits.")], id="2fa")
    password = PasswordField('password_label', validators=[InputRequired(message="Password cannot be blank."), Length(message="Password must be between 8 and 32 characters in length.", min=8, max=32)],id="pword")
    submit_button = SubmitField('Register', validators=[check_duplicate_user])

class LoginForm(FlaskForm):
    username = StringField('username_label',validators=[InputRequired(message="Username cannot be blank.")])
    password = PasswordField('password_label',validators=[InputRequired(message="Password cannot be blank.")])
    telephone = StringField('telephone_label', validators=[InputRequired(message="Telephone cannot be blank.")])    
    submit_button = SubmitField('Login', validators=[check_login])

class CheckSpellingForm(FlaskForm):
    inputtext = StringField('inputtext_label', validators=[InputRequired(message="Please supply SpellHell with text.")])
    submit_button = SubmitField('Go To Hell')
