""" build a simple drop box """

from datetime import datetime
from hashlib import sha256
from cfg import config
from utily import get_random_string
from flask import Flask, render_template, request, redirect, session
from flask_pymongo import PyMongo


app = Flask(__name__)
app.config["MONGO_URI"] = config['MONGO_URI']
mongo = PyMongo(app)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

""" function retun the home page """


@app.route("/")
def login(): 
    if 'userToken' in session:
        token_validate = mongo.db.user_token.find_one({
            'sessionHash': session['userToken']})
        if token_validate is not None:
            return redirect("/dashboard")
    signupSuccess = ""
    if 'signupSuccess' in session:
        signupSuccess = session['signupSuccess']
        session.pop('signupSuccess', None)
    error = ""
    if 'error' in session:
        error = session['error']
        session.pop('error', None)
    return render_template("index2.html", 
                           signupSuccess=signupSuccess,
                           error=error)


@app.route("/register")
def register(): 
    """ getting the forgot_password path """
    error = ""
    if 'error' in session:
        error = session['error']
        session.pop('error', None)
    return render_template("register.html", error=error)


@app.route("/handle_registration", methods=['POST'])
def handle_registration():
    """ Handle user registration """
    try:
        email = request.form['email']
        password = request.form['password']
        cpassword = request.form['cpassword']
    except KeyError as e:
        session['error'] = "Missing field: " + str(e)
        return redirect('/register')

    # Email validation
    if '@' not in email or '.' not in email:
        session['error'] = "Invalid email format"
        return redirect('/register')

    # Password confirmation check
    if password != cpassword:
        session['error'] = "Passwords do not match"
        return redirect('/register')

    # Check if email already exists in the database
    existing_user = mongo.db.users.find_one({"email": email})
    if existing_user:
        session['error'] = "Email already taken"
        return redirect('/register')

    # Hashing the password
    hashed_password = sha256(password.encode('utf-8')).hexdigest()

    # Creating user record
    mongo.db.users.insert_one({
        'email': email,
        'password': hashed_password,
        'name': '',
        'lastLoginDate': None,
        "CreatedAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow(),
    })

    session['signupSuccess'] = 'Your user account is now ready. Login now.'
    return redirect('/')


@app.route("/forgot_password")
def forgot_password(): 
    """ getting the forgot_password path """
    return render_template("forgot_password.html")


@app.route("/confirm_reset")
def confirm_reset(): 
    """ getting the forgot_password path """
    return render_template("confirm_reset.html")


@app.route('/checkeing_login', methods=['POST'])
def checkeing_login():
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError as e:
        session['error'] = "Missing field: " + str(e)
        return redirect('/')
    user_document = mongo.db.users.find_one({"email": email})
    if user_document is None:
        session['error'] = "No account exists for this User"
        return redirect('/register')
    password_hash = sha256(password.encode('utf-8')).hexdigest()

    if user_document['password'] != password_hash:
        session['error'] = "invalid credential for this user"
        return redirect('/')
    
    random_string = get_random_string()
    randomSessionHash = sha256(random_string.encode('utf-8')).hexdigest()
    # generate toke and save
    mongo.db.user_token.insert_one({
        'userId': user_document['_id'],
        'sessionHash': randomSessionHash,
        "CreatedAt": datetime.utcnow(),

    })
    session['userToken'] = randomSessionHash
    return redirect('/dashboard')


@app.route('/dashboard')
def dashboard():
    if not 'userToken' in session:
        session['error'] = "You must login to access this page"
        return redirect('/')
    token_document = mongo.db.user_token.find_one({
        'sessionHash': session['userToken']
    })
    if token_document is None:
        session.pop('userToken', None)
        session['error'] = "You must login to again"
        return redirect('/')
    return render_template("dashboard.html")


@app.route('/logout')
def logout():
    session.pop('userToken', None)
    session['signupSuccess'] = "You are now loggout out."
    return redirect('/')