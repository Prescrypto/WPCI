from tornado.web import  os
import tornado
from tornado import gen, ioloop
import ast
from handlers.apiBaseHandler import BaseHandler
import jwt
import config as conf
import datetime
import json
import fitz
from models import User, Nda
from models.mongoManager import ManageDB
import tempfile
import time
import hashlib
import os
import subprocess
import glob
from handlers.emailHandler import write_email
import config as conf

SECRET = conf.SECRET
RENDER_EMAIL = "render_and_send_by_email"
RENDER_HASH = "render_sethash_and_download"
RENDER_NOHASH = "render_and_download"
RENDER_URL= "render_by_url_parameters"


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

def store_petition(remote_url, petition_type, username='anonymous'):
    result = False
    mydb = None
    try:
        collection = "Petitions"
        mydb = ManageDB(collection)
        result = mydb.insert_json({"username": username, "timestamp": time.time(), "remote_url": remote_url, "petition_type": petition_type})

    except Exception as error:
        print("storing petition", error)

    finally:
        if mydb is not None:
            mydb.close()

    return result


def create_email_pdf(repo_url, email, main_tex="main.tex"):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    new_name = ''
    # Axis for the pdf header
    AXIS_X = 35
    AXIS_Y = 35
    AXIS_Y_LOWER = 50

    if email is None or email== "":
        return("NO EMAIL TO HASH")
    email = email.strip()

    store_petition(repo_url, RENDER_HASH, email)
    print("No private access")

    watermark = "Copy generated for: "+ email

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
            pointa = fitz.Point(AXIS_X,AXIS_Y)
            pointb = fitz.Point(AXIS_X, AXIS_Y_LOWER)
            document = fitz.open(new_name)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize = 11, fontname = "Helvetica")
                page.insertText(pointb, text="uid: " + complete_hash, fontsize=11, fontname="Helvetica")
            document.save(new_name, incremental=1)
            document.close()

            write_email([email], "Documentation", "documentation.pdf", new_name)

        except IOError as e:
            print('IOError', e)
            return("IO ERROR")
        except Exception as e:
            print("other error", e)
            return("ERROR PRIVATE REPO OR COULDN'T FIND MAIN.TEX")
    return True


def create_email_pdf_auth(repo_url, userjson, email, main_tex="main.tex"):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    new_name = ''
    #Axis for the pdf header
    AXIS_X = 35
    AXIS_Y = 35
    AXIS_Y_LOWER = 50

    user = User.User(userjson.get("username"), userjson.get("password"))
    github_token = user.get_attribute('github_token')
    if github_token is None or github_token == '':
        return ("ERROR NO GITHUB TOKEN")

    try:
        repo_url = "https://" + github_token + ":x-oauth-basic@" + repo_url.split("://")[1]
    except:
        return ("Invalid GIT Repository URL")

    store_petition(repo_url, RENDER_HASH, user.username)
    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'
    if email is None or email == "":
        email = user.username
    email = email.strip()
    watermark = "Copy generated for: " + email

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)
            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            complete_hash = get_hash(email, run_git_rev_parse.decode('UTF-8'))
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex " + main_tex, shell=True,
                                               cwd=filesdir)
            new_name = filesdir + "/" + main_tex.split(".")[0] + ".pdf"
            pointa = fitz.Point(AXIS_X, AXIS_Y)
            pointb = fitz.Point(AXIS_X, AXIS_Y_LOWER)
            document = fitz.open(new_name)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize=11, fontname="Helvetica")
                page.insertText(pointb, text="uid: " + complete_hash, fontsize=11, fontname="Helvetica")
            document.save(new_name, incremental=1)
            document.close()

            write_email([email], "Documentation", "documentation.pdf", new_name)


        except IOError as e:
            print('IOError', e)
            return ("IO ERROR")
        except Exception as e:
            print("other error", e)
            return ("ERROR")
    return True


def create_download_pdf_auth(repo_url, userjson, email, main_tex="main.tex"):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    new_name = ''
    # Axis for the pdf header
    AXIS_X = 35
    AXIS_Y = 35
    AXIS_Y_LOWER = 50

    user = User.User(userjson.get("username"), userjson.get("password"))
    github_token = user.get_attribute('github_token')
    if github_token is None or github_token == '':
        return("ERROR NO GITHUB TOKEN")

    try:
        repo_url = "https://"+github_token+":x-oauth-basic@"+repo_url.split("://")[1]
    except:
        return("Invalid GIT Repository URL")

    store_petition(repo_url, RENDER_HASH, user.username)
    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'
    if email is None or email == "":
        email = user.username
    watermark = "Copy generated for: " + email

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)
            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            complete_hash = get_hash(email, run_git_rev_parse.decode('UTF-8'))
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex "+ main_tex , shell=True, cwd=filesdir)
            new_name = filesdir+"/"+ main_tex.split(".")[0]+ ".pdf"
            pointa = fitz.Point(AXIS_X, AXIS_Y)
            pointb = fitz.Point(AXIS_X, AXIS_Y_LOWER)
            document = fitz.open(new_name)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize = 11, fontname = "Helvetica")
                page.insertText(pointb, text="uid: " + complete_hash, fontsize=11, fontname="Helvetica")
            #document.save(filesdir+"/temp_"+new_name, garbage=4, deflate=1) #this parameters are used for cleanup the  pdf
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

def create_download_pdf(repo_url, email, main_tex="main.tex"):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    new_name = ''
    # Axis for the pdf header
    AXIS_X = 35
    AXIS_Y = 35
    AXIS_Y_LOWER = 50

    if email is None or email== "":
        return("NO EMAIL TO HASH")

    store_petition(repo_url, RENDER_HASH, email)
    print("No private access")

    watermark = "Copy generated for: "+ email

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
            pointa = fitz.Point(AXIS_X, AXIS_Y)
            pointb = fitz.Point(AXIS_X, AXIS_Y_LOWER)
            document = fitz.open(new_name)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize = 11, fontname = "Helvetica")
                page.insertText(pointb, text="uid: " + complete_hash, fontsize=11, fontname="Helvetica")
            #document.save(filesdir+"/temp_"+new_name, garbage=4, deflate=1) #this parameters are used for cleanup the  pdf
            document.save(new_name, incremental=1)
            document.close()

            pdffile = open(new_name, 'rb').read()
            return(pdffile)

        except IOError as e:
            print('IOError', e)
            return("IO ERROR")
        except Exception as e:
            print("other error", e)
            return("ERROR PRIVATE REPO OR COULDN'T FIND MAIN.TEX")


def render_pdf(repo_url, main_tex= "main.tex"):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    new_name = ''
    store_petition(repo_url, RENDER_NOHASH, "")
    print("No private access")

    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)
            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex " + main_tex, shell=True, cwd=filesdir)
            new_name = filesdir + "/" + main_tex.split(".")[0] + ".pdf"
            pdffile = open(new_name, 'rb').read()
            return (pdffile)


        except IOError as e:
            print('IOError', e)
            return False
        except Exception as e:
            print("other error", e)
            return False


def create_dynamic_endpoint(pdf, pdf_url, wp_url, wp_main_tex, org_name):
    base_url= conf.BASE_URL
    PDF_VIEW_URL = 'pdf/'
    try:
        nda = Nda.Nda(pdf, pdf_url, wp_url, wp_main_tex, org_name)
        if not nda.find():
            nda.create()
        else:
            nda.update()

        return base_url+PDF_VIEW_URL+nda.id

    except Exception as e:
        print("error creating nda",e)
        return False


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
class PostRepoHash(BaseHandler):
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

            if json_data.get("email") is None or json_data.get("email") == "":
                email = ""
            else:
                email = json_data.get("email")
            userjson = ast.literal_eval(userid)
            result = create_email_pdf_auth(json_data.get("remote_url"),userjson, email, main_tex)
            if result:
                self.write(json.dumps({"response": "done"}))
            else:
                self.write(json.dumps({"response": "Error"}))

        except Exception as e:
            print("error on clone", e)
            self.write(json.dumps({"response": "Error"}))


class RenderUrl(BaseHandler):
    '''recives a get with the github repository url as parameters and renders it to PDF with clone_repo'''

    def get(self):
        try:
            repo_url = self.get_argument('url', "")
            main_tex = self.get_argument('maintex', "main.tex")
            email = self.get_argument('email', "")
            result = create_email_pdf(repo_url, email, main_tex)
            if result:
                self.write(json.dumps({"response":"done"}))
            else:
                self.write(json.dumps({"response": "Error"}))


        except Exception as e:
            print("error on clone", e)
            self.write(json.dumps({"response": "Error"}))

@jwtauth
class PostWpNda(BaseHandler):
    '''recives a post with the github repository url and renders it to PDF with clone_repo'''

    def post(self, userid):
        wp_url = None
        pdf_contract = None
        pdf_url = None
        wp_main_tex = "main.tex"
        org_name = None
        json_data = json.loads(self.request.body.decode('utf-8'))
        try:
            if json_data.get("wp_url") is None or json_data.get("wp_url") == "":
                self.write(json.dumps({"response": "Error, White paper url not found"}))
            else:
                wp_url = json_data.get("wp_url")

            if json_data.get("org_name") is None or json_data.get("org_name") == "":
                self.write(json.dumps({"response": "Error, organization name not found"}))
            else:
                org_name = json_data.get("org_name")

            if json_data.get("wp_main_tex") is not None and json_data.get("wp_main_tex") != "":
                wp_main_tex = json_data.get("wp_main_tex")


            if json_data.get("pdf") is not None and json_data.get("pdf") != "":
                pdf_contract = json_data.get("pdf")

            if json_data.get("pdf_url") is not None and json_data.get("pdf_url") != "":
                pdf_url = json_data.get("pdf_url")

            userjson = ast.literal_eval(userid)
            result = create_dynamic_endpoint(pdf_contract, pdf_url, wp_url, wp_main_tex, org_name)
            if result is not False:
                self.write(json.dumps({"endpoint": result}))
            else:
                self.write(json.dumps({"response": "Error"}))

        except Exception as e:
            print("error creating endpoint", e)
            self.write(json.dumps({"response": "Error"}))


"""No autentication endpoint"""
class HelloWorld(BaseHandler):
    def get(self):
        self.write(json.dumps({"response": "hello world"}))

    def post(self):
        self.write(json.dumps({"response": "hello world"}))



