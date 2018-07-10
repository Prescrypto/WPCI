from tornado.web import  os
import tornado
import ast
from handlers.apiBaseHandler import BaseHandler
import jwt
import config as conf
import datetime
import json
import fitz
from models import User
import tempfile
import time
import hashlib
import os
import subprocess
import glob
import base64
from handlers.emailHandler import write_email

SECRET = conf.SECRET


def encode_auth_token(user):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=3600),
            "iat": datetime.datetime.utcnow(),
            "username": user.username,
            "password": user.password
        }
        return jwt.encode(
            payload,
            SECRET,
            algorithm="HS256"
        )
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: json user
    """
    try:
        payload = jwt.decode(auth_token, SECRET)
        return payload
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


def authenticate(password, username):
    if not (username and password):
        return False

    user = User.User(username, password)
    if user.check():
        token_auth = encode_auth_token(user)

        return token_auth

    else:
        return False

def validate_token(access_token):
    """Verifies that an access-token is valid and
    meant for this app."""
    try:
        method, token = access_token.split(" ")
        user_id = decode_auth_token(token.strip('"'))

    except Exception as e:
        print (e)
        return False

    return user_id


def jwtauth(handler_class):
    ''' Handle Tornado JWT Auth '''
    userid = None
    def wrap_execute(handler_execute):
        def require_auth(handler, kwargs):
            auth = handler.request.headers.get('Authorization')

            if auth:
                parts = auth.split()

                if parts[0].lower() != 'bearer':
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()
                elif len(parts) == 1:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()
                elif len(parts) > 2:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()

                try:
                    userid = validate_token(auth)

                    if userid is False:
                        handler._transforms = []
                        handler.set_status(403)
                        handler.write("Forbidden")
                        handler.finish()

                    if 'username' not in userid:
                        handler._transforms = []
                        handler.set_status(401)
                        handler.write("Forbidden")
                        handler.finish()

                    kwargs["userid"] = str(userid)

                except Exception as e:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write(e)
                    handler.finish()
            else:
                handler._transforms = []
                handler.write("Missing authorization")
                handler.finish()

            return True

        def _execute(self, transforms, *args, **kwargs):

            try:
                require_auth(self, kwargs)
            except Exception as e:
                print (e)
                return False

            return handler_execute(self, transforms, *args, **kwargs)

        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class


def authenticate_json(json_data):
    '''gets the information from the payload and verificates if it is registered'''
    try:
        username = json_data.get("username")
        password = json_data.get("password")
    except:
        return False

    if not (username and password):
        return False

    user = User.User(username,password)

    if user.check():
        token_auth = encode_auth_token(user)

        return token_auth.decode("utf-8")

    else:
        return False

def get_hash(email, git_sha):
    hashed_payload = None
    timestamp = str(time.time())
    payload = hashlib.sha256(timestamp.encode('utf-8')).hexdigest() + hashlib.sha256(email.encode('utf-8')).hexdigest() + git_sha
    hash_object = hashlib.sha256(payload.encode('utf-8'))
    hashed_payload = hash_object.hexdigest()

    return hashed_payload

def create_email_pdf(repo_url, email, main_tex="main.tex"):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    new_name = ''
    clone = 'git clone ' + repo_url

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex "+ main_tex , shell=True, cwd=filesdir)
            new_name = main_tex.split(".")[0]+ ".pdf"
            write_email([email], "testing pdflatex",new_name , filesdir+"/")

            return("Email Sent")

        except IOError as e:
            print('IOError', e)
            return("IO ERROR")
        except Exception as e:
            print("other error", e)
            return("ERROR")

def create_download_pdf(repo_url, email, main_tex="main.tex"):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    new_name = ''
    img_filename = 'testimage.jpg'
    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)
            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            complete_hash = get_hash(email, run_git_rev_parse.decode('UTF-8'))
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex "+ main_tex , shell=True, cwd=filesdir)
            new_name = filesdir+"/"+ main_tex.split(".")[0]+ ".pdf"
            point = fitz.Point(50,50)
            document = fitz.open(new_name)
            for page in document:
                page.insertText(point, text=complete_hash, fontsize = 11, fontname = "Helvetica")
            #document.save(filesdir+"/temp_"+new_name, garbage=4, deflate=1) #Estos parametros resultan en compresion del pdf
            document.save(new_name, incremental=1)
            document.close()

            pdffile = open(new_name, 'rb').read()
            return(pdffile)

        except IOError as e:
            print('IOError', e)
            return("IO ERROR")
        except Exception as e:
            print("other error", e)
            return("ERROR")


def create_each_pdf(repo_url):
    '''renders one by one all the .tex on a repo'''
    repo_name = ''
    new_name = ''
    clone = "git clone " + repo_url
    try:
        repo_name= repo_url.split("/")[-1].split(".")[0]
    except Exception as e:
        print('couldnt find the name or not valid url')
        return("ERROR")

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            filesdir = os.path.join(tmpdir, repo_name)
            subprocess.call(clone, shell=True, cwd=tmpdir)
            files = glob.glob(filesdir + '/*.tex')

            for name in files:
                subprocess.call("pdflatex "+ name, shell=True, cwd=tmpdir)
                try:
                    new_name = name.split("/")[-1].split(".")[0] + ".pdf"
                except:
                    print("main file name not found")
                    return("ERROR ON MAIN FILE")

                write_email(["valerybriz@gmail.com"], "testing pdflatex",new_name , tmpdir+"/")

            return("Email Sent")

        except IOError as e:
            print('IOError', e)
            return("IO ERROR")


@jwtauth
class APINotFoundHandler(BaseHandler):
    '''if the endpoint doesn't exists then it will response with this code'''
    def options(self, *args, **kwargs):
        self.set_status(200)
        self.finish()

class AuthLoginHandler(BaseHandler):
    '''receives the username and password to retrive a token'''
    def post(self):
        json_data = json.loads(self.request.body.decode('utf-8'))
        token_auth = authenticate_json(json_data)
        if token_auth is False:
            status_code =401
            response = {'status': '401', 'message': 'Incorrect username or password'}
        else:
            status_code = 200
            response = {"token": token_auth}

        self.write_json(response, status_code)

    def set_current_user(self, user):
        if user:
            self.set_secure_cookie("user", tornado.escape.json_encode(user))
        else:
            self.clear_cookie("user")

class RegisterUser(BaseHandler):
    '''receives a payload with the user data and stores it on the bd'''
    def post(self):
        try:
            json_data = json.loads(self.request.body.decode('utf-8'))
            user = User.User(json_data.get("username"), json_data.get("password"))
            if not user.find():
                user.create()
                self.write(json.dumps({"response": "user created successfully"}))
            else:
                self.write(json.dumps({"response": "user already exists"}))
        except:
            self.write(json.dumps({"response": "error registering user"}))

@jwtauth
class HelloWorld2(BaseHandler):
    def get(self, userid):
        self.write(json.dumps({"response": "hello world2"}))

    def post(self, userid):
        self.write(json.dumps({"response": "hello world2"}))

@jwtauth
class PostRepo(BaseHandler):
    '''recives a post with the github repository url and renders it to PDF with clone_repo'''
    def get(self, userid):
        self.write(json.dumps({"response": "GET not found"}))

    def post(self, userid):
        json_data = json.loads(self.request.body.decode('utf-8'))
        try:
            if json_data.get("main_tex") is None or json_data.get("main_tex") == "":
                main_tex = "main.tex"
            else:
                main_tex = json_data.get("main_tex")
            userjson = ast.literal_eval(userid)
            result = create_download_pdf(json_data.get("remote_url"),userjson.get('username'), main_tex)
            self.write(json.dumps({"pdf": base64.b64encode(result)}))
        except Exception as e:
            print("error on clone", e)


"""No autentication endpoint"""
class HelloWorld(BaseHandler):
    def get(self):
        self.write(json.dumps({"response": "hello world"}))

    def post(self):
        self.write(json.dumps({"response": "hello world"}))



