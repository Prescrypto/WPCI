from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from flask_oauthlib.client import OAuth
from tornado.wsgi import WSGIContainer, WSGIAdapter
import config as conf
from models.mongoManager import ManageDB
from handlers.routes import jwtauth, validate_token
from models import User


app = Flask(__name__)
app.debug = True
app.secret_key = conf.SECRET
oauth = OAuth(app)

oauth_app = WSGIContainer(app)

github = oauth.remote_app(
    'github',
    consumer_key=conf.CONSUMER_KEY,
    consumer_secret=conf.CONSUMER_SECRET,
    request_token_params={'scope': 'repo'},
    base_url=conf.GITHUB_API_URL,
    request_token_url=None,
    access_token_method='POST',
    access_token_url= conf.GITHUB_OAUTH_URI +'access_token',
    authorize_url= conf.GITHUB_OAUTH_URI +'authorize'
)


@app.route('/api/v1/git/index')
def index():
    error =request.args.get('error')
    if 'user' in session:
        if 'github_token' in session:
            #me = github.get('user') #return jsonify(me.data) # we can get this information if there is a github_token at the session
            return render_template('index.html', error=error)
        else:
            return render_template('index.html', error= error)
    else:
        return redirect(url_for('login'))



@app.route('/api/v1/git/login', methods=['GET', 'POST'])
def login():
    error=''
    if 'user' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if request.form['username'] and request.form['password']:
            user = User.User(request.form.get("username"), request.form.get("password"))
            if user.check():
                session["user"] = user.__dict__
                github_token = user.get_attribute("github_token")
                if github_token is not None:
                    session["github_token"] = github_token
                else:
                    print("no github session token")
                return redirect(url_for('index'))
            else:
                error = 'Invalid Credentials. Please try again.'

        else:
            error = 'Invalid Credentials. Please try again.'

    return render_template('login.html', error=error)


@app.route('/api/v1/git/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        if request.form['username'] and request.form['password']:
            register_user = User.User(request.form['username'],request.form['password'])
            if register_user.find() is not True:
                register_user.create()
                session["user"] = register_user.__dict__
                return redirect(url_for('index'))
            else:
                error = "User already Exists"
    return render_template('register.html', error=error)


@app.route('/api/v1/git/gitlogin')
def gitlogin():
    return github.authorize(callback=url_for('authorized', _external=True))



@app.route('/api/v1/git/logout')
def logout():
    session.pop('user', None)
    session.pop('github_token', None)
    return redirect(url_for('index'))


@app.route('/api/v1/git/login/authorized')
def authorized():
    error = None
    resp = github.authorized_response()
    if resp is None or resp.get('access_token') is None:
        print("no access token")
        error= 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            resp
        )
    try:
        session['github_token'] = (resp['access_token'], '')
        if session['github_token'] is not None and session['github_token'][0] != '':
            user = User.User(session["user"].get("username"), session["user"].get("password"))
            user.github_token = resp['access_token']
            user.update()
    except:
        print("error getting Token")
        error= "error getting Token"

    #me = github.get('user') return jsonify(me.data)  #we can get the user information from github
    return redirect(url_for('index', error=error))


@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')

