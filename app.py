import os, time
import subprocess
import sqlalchemy
from flask import Flask, flash, render_template, url_for, request, session
from werkzeug.utils import redirect
from wtform import *
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

app = Flask(__name__)
app.secret_key = 'This is one super secret key!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/spellhell.sqlite3'

db = SQLAlchemy(app)
from models import db
db.create_all()
db.session.commit()
defaultAdmin = Users(username="admin", password=pbkdf2_sha512.hash("Administrator@1"), telephone="12345678901", admin="1")
adminLoginTest = Authentication(user_id=1, action="Login", time=time.asctime( time.localtime(time.time())))
adminLoginTest2 = Authentication(user_id=1, action="Logout", time=time.asctime( time.localtime(time.time())))
adminLoginTest3 = Authentication(user_id=1, action="Login", time=time.asctime( time.localtime(time.time())))
db.session.add(adminLoginTest)
db.session.add(adminLoginTest2)
db.session.add(adminLoginTest3)
db.session.add(defaultAdmin)
db.session.commit()

@app.route("/", methods=['GET', 'POST'])
def index():
   return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    displayHeading = "SpellHell Registration"
    reg_form = RegistrationForm()

    if session.get('user_context'):
        return redirect(url_for("spell_check"))
 
    if request.method == 'POST':
        if reg_form.validate_on_submit():
            username = escape(reg_form.username.data)
            password = escape(reg_form.password.data)
            telephone = escape(reg_form.telephone.data)

            displayMessage = "Registration success!"

            hashed_password = pbkdf2_sha512.hash(password)
            user = Users(username=username, password=hashed_password, telephone=telephone, admin="0")

            db.session.add(user)
            db.session.commit()

        else:
            displayMessage = "Registration failure!"

        return render_template("register.html", form=reg_form, displayHeading=displayHeading, displayMessage=displayMessage)

    if request.method == 'GET':
        displayMessage = ""
        return render_template("register.html", form=reg_form, displayHeading=displayHeading, displayMessage=displayMessage)

@app.route("/login", methods=['GET', 'POST'])
def login():
    displayHeading = "SpellHell Login"
    login_form = LoginForm()

    if session.get('user_context'):
        return redirect(url_for("spell_check"))

    if request.method == 'POST':
        if login_form.validate_on_submit():
            current_user = Users.query.filter_by(username=request.form['username']).first()
            session['user_context'] = current_user.username
            session['user_id'] = current_user.id
            session['admin'] = current_user.admin
            displayMessage = "Login success!"
            
            login_time = Authentication(user_id=session['user_id'], action="Login", time=time.asctime( time.localtime(time.time())))
            db.session.add(login_time)
            db.session.commit()
        else:
            displayMessage = "Login failure!"
        return render_template("login.html", form=login_form, displayHeading=displayHeading, displayMessage=displayMessage)

    if request.method == 'GET':
        displayMessage = ""
        return render_template("login.html", form=login_form, displayHeading=displayHeading, displayMessage=displayMessage)

@app.route("/spell_check", methods=['GET', 'POST'])
def spell_check():
    displayHeading = "Spell Checker"
    check_spelling = CheckSpellingForm()
    currpath = os.getcwd()

    if not session.get('user_context'):
            return redirect(url_for("login"))
    
    if request.method == 'POST':
        if check_spelling.validate_on_submit():
            inputtext = escape(check_spelling.inputtext.data)
            inputfile = open("./static/userinput.txt", "w")
            inputfile.writelines(inputtext)
            inputfile.close()

            syscall = subprocess.check_output(
            [currpath + '/static/a.out', currpath + '/static/userinput.txt', currpath + '/static/wordlist.txt']).decode('utf-8')
            misspelled = syscall.replace("\n", " | ")[:-2]
            query_log = Queries(user_id=session['user_id'], user_name=session['user_context'], time=time.asctime( time.localtime(time.time())), querytext=inputtext, queryresults=misspelled)
            db.session.add(query_log)
            db.session.commit()
        return render_template("spell_check.html", form=check_spelling, misspelled=misspelled, inputtext=inputtext)

    if request.method == 'GET':
        displayMessage = ""
        return render_template("spell_check.html", displayMessage=displayMessage, form=check_spelling)

@app.route("/history", defaults={"query": None}, methods=['POST', 'GET'])
@app.route("/history/<query>")
def history(query):
    displayMessage = "Query History"
    query_history = QueryHistoryForm()
    user = Users.query.filter_by(id=session['user_id']).first()
    
    if not session.get('user_context'):
        return redirect(url_for('login'))
    if query != None:
        query_id = int(query.replace("query", ""))
        if session['admin'] == "1":
            queries = Queries.query.filter_by(id=query_id).first()
            user = Users.query.filter_by(id=queries.user_id).first()
        else:
            queries = Queries.query.filter_by(user_id=session.get('user_id'), id=query_id).first()
        if queries is None:
            flash("Query ID does not exist.")
        
        return render_template("review.html", queries=queries, user=user)
    else:
        if session.get('admin') == "1" and query_history.validate_on_submit():
            queries = Queries.query.filter_by(user_name=escape(query_history.user_name.data)).all()
            count = Queries.query.filter_by(user_name=escape(query_history.user_name.data)).count()
        else:
            queries = Queries.query.filter_by(user_id=session['user_id']).all()
            count = Queries.query.filter_by(user_id=session['user_id']).count() 
        return render_template("history.html", queries=queries, count=count, user=user, form=query_history)


@app.route('/login_history', methods=['GET', 'POST'])
def login_history():
    displayMessage = "Authentication History"
    auth_history = AuthHistoryForm()
    user_id = escape(auth_history.user_id.data)
    
    if not session.get('user_context'):
        return redirect(url_for('login'))
    if session.get('admin') != "1":
        flash('Not authorized for login history search')
        return redirect(url_for('index'))
    if auth_history.validate_on_submit():
        auth_logs = Authentication.query.filter_by(user_id=user_id).all()
        if auth_logs is None:
            flash('No authentication history for User ID.')
            return redirect(url_for('login_history'))
        return render_template("login_history.html", displayMessage=displayMessage, form=auth_history, user_id=user_id, auth_logs=auth_logs)
    return render_template('login_history.html', title='Login History', form=auth_history)

@app.route('/logout')
def logout():
    if session.get('user_context'):
        logout_time = Authentication(user_id=session['user_id'], action="Logout", time=time.asctime( time.localtime(time.time())))
        db.session.add(logout_time)
        db.session.commit()
        session.pop('user_context', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
