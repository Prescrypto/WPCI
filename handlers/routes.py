#python
import logging
import ast
import jwt
import datetime
import json
import tempfile
import time
import hashlib
import os
import subprocess
import glob
import base64
import io

#web app
from tornado.web import  os
import tornado
from tornado import gen, ioloop
import jinja2

#google oauth
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.http import MediaIoBaseDownload

#pdf context
import fitz

#internal
from handlers.apiBaseHandler import BaseHandler
import config as conf
from models import User, Document
from models.mongoManager import ManageDB
from handlers.emailHandler import Mailer
from utils import *

latex_jinja_env = jinja2.Environment(
	block_start_string = '\BLOCK{',
	block_end_string = '}',
	variable_start_string = '${{',
	variable_end_string = '}}$',
	comment_start_string = '\#{',
	comment_end_string = '}',
	line_statement_prefix = '%%line',
	line_comment_prefix = '%#line',
	trim_blocks = True,
	autoescape = False,
	loader = jinja2.FileSystemLoader(os.path.abspath('/'))
)

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

SECRET = conf.SECRET
RENDER_EMAIL = "render_and_send_by_email"
RENDER_HASH = "render_sethash_and_download"
RENDER_NOHASH = "render_and_download"
RENDER_URL= "render_by_url_parameters"
BASE_PATH = "/docs/"

#SMTP VARIABLES
SMTP_PASS = conf.SMTP_PASS
SMTP_USER = conf.SMTP_USER
SMTP_EMAIL = conf.SMTP_EMAIL
SMTP_ADDRESS = conf.SMTP_ADDRESS
SMTP_PORT = conf.SMTP_PORT

# Axis for the pdf header
AXIS_X = 15
AXIS_Y = 500
AXIS_Y_GOOGLE = 200
AXIS_X_LOWER = 28
WATERMARK_ROTATION = 90
WATERMARK_FONT = "Times-Roman"
WATERMARK_SIZE = 10
FLIP_MATRIX = fitz.Matrix(1.0, -1.0) # this generates [a=1,b=0,c=0,d=-1,e=0,f= 0]

# The default message to be sent in the body of the email
DEFAULT_HTML_TEXT = "<h3>Hello,</h3>\
        <p>You will find the documentation you requested attached, thank you very much for your interest.</p>\
        <p>Best regards,</p>"


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
        logger.info(e)
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
                logger.info(e)
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


def store_petition(remote_url, petition_type, username='anonymous'):
    result = False
    mydb = None
    try:
        collection = "Petitions"
        mydb = ManageDB(collection)
        result = mydb.insert_json({"username": username, "timestamp": time.time(), "remote_url": remote_url, "petition_type": petition_type})

    except Exception as error:
        logger.info("storing petition"+ str(error))

    finally:
        if mydb is not None:
            mydb.close()

    return result

def create_email_pdf(repo_url, user_email, email_body_html, main_tex="main.tex", email_body_text="", options ={}):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    file_full_path = ''
    attachments_list = []
    new_main_tex = "main2.tex"
    ATTACH_CONTENT_TYPE = 'octet-stream'
    mymail = Mailer(username=SMTP_USER, password=SMTP_PASS, host=SMTP_ADDRESS, port=SMTP_PORT)

    if user_email is None or user_email== "":
        return("NO EMAIL TO HASH")
    user_email = user_email.strip()

    store_petition(repo_url, RENDER_HASH, user_email)
    logger.info("No private access")

    watermark = "Document generated for: "+ user_email

    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            timestamp = str(time.time())
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)

            if options != {}: #if there are special conditions to render
                # modify the original template:
                template = latex_jinja_env.get_template(filesdir +"/"+main_tex)
                renderer_template = template.render(**options)
                with open(filesdir + "/" + new_main_tex, "w") as f:  # saves tex_code to outpout file
                    f.write(renderer_template)
            else:
                new_main_tex = main_tex

            file_full_path = filesdir + "/" + new_main_tex.split(".")[0] + ".pdf"
            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            complete_hash = get_hash([timestamp, user_email], [run_git_rev_parse.decode('UTF-8')])
            run_latex_result = subprocess.call("texliveonfly --compiler=latex " + new_main_tex, shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("bibtex " + new_main_tex.split(".")[0], shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex " + new_main_tex, shell=True,
                                               cwd=filesdir)

            pointa = fitz.Point(AXIS_X,AXIS_Y)
            pointb = fitz.Point(AXIS_X_LOWER, AXIS_Y)
            document = fitz.open(file_full_path)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize=10, fontname=WATERMARK_FONT, rotate=WATERMARK_ROTATION)
                page.insertText(pointb, text="DocId: " + complete_hash, fontsize=10, fontname=WATERMARK_FONT,
                                rotate=WATERMARK_ROTATION)
            document.save(file_full_path, incremental=1)
            document.close()

            attachment = dict(file_type=ATTACH_CONTENT_TYPE, file_path=file_full_path, filename="documentation.pdf")
            attachments_list.append(attachment)
            mymail.send(subject="Documentation",email_from=SMTP_EMAIL,emails_to=[user_email],emails_bcc=[conf.ADMIN_EMAIL],
                        attachments_list=attachments_list, text_message=email_body_text,
                        html_message=email_body_html)

        except IOError as e:
            logger.info('IOError'+ str(e))
            return("IO ERROR")
        except Exception as e:
            logger.info("other error"+ str(e))
            return("ERROR PRIVATE REPO OR COULDN'T FIND MAIN.TEX")
    return True


def create_email_pdf_auth(repo_url, userjson, user_email, email_body_html, main_tex="main.tex", email_body_text ="", options={}):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    file_full_path = ''
    attachments_list = []
    new_main_tex = "main2.tex"
    ATTACH_CONTENT_TYPE = 'octet-stream'
    mymail = Mailer(username=SMTP_USER, password=SMTP_PASS, host=SMTP_ADDRESS, port=SMTP_PORT)

    user = User.User(userjson.get("username"), userjson.get("password"))
    github_token = user.get_attribute('github_token')
    if github_token is None or github_token == '':
        return ("ERROR NO GITHUB TOKEN")

    try:
        repo_url = "https://{}:x-oauth-basic@{}".format(github_token,repo_url.split("://")[1])
    except:
        return ("Invalid GIT Repository URL")

    store_petition(repo_url, RENDER_HASH, user.username)
    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'
    if user_email is None or user_email == "":
        user_email = user.username
    user_email = user_email.strip()
    watermark = "Document generated for: " + user_email

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            timestamp = str(time.time())
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)
            if options != {}: #if there are special conditions to render
                # modify the original template:
                template = latex_jinja_env.get_template(filesdir +"/"+main_tex)
                renderer_template = template.render(**options)
                with open(filesdir + "/" + new_main_tex, "w") as f:  # saves tex_code to outpout file
                    f.write(renderer_template)
            else:
                new_main_tex = main_tex

            file_full_path = filesdir + "/" + new_main_tex.split(".")[0] + ".pdf"
            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            complete_hash = get_hash([timestamp, user_email], [run_git_rev_parse.decode('UTF-8')])
            run_latex_result = subprocess.call("texliveonfly --compiler=latex " + new_main_tex, shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("bibtex " + new_main_tex.split(".")[0], shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex " + new_main_tex, shell=True,
                                               cwd=filesdir)
            pointa = fitz.Point(AXIS_X, AXIS_Y)
            pointb = fitz.Point(AXIS_X_LOWER, AXIS_Y)
            document = fitz.open(file_full_path)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize=WATERMARK_SIZE, fontname=WATERMARK_FONT,
                                rotate= WATERMARK_ROTATION)
                page.insertText(pointb, text="DocId: " + complete_hash, fontsize=WATERMARK_SIZE,
                                fontname=WATERMARK_FONT, rotate= WATERMARK_ROTATION)
            document.save(file_full_path, incremental=1)
            document.close()

            attachment = dict(file_type=ATTACH_CONTENT_TYPE, file_path=file_full_path, filename="documentation.pdf")
            attachments_list.append(attachment)
            mymail.send(subject="Documentation", email_from=SMTP_EMAIL, emails_to=[user_email],emails_bcc=[conf.ADMIN_EMAIL],
                        attachments_list=attachments_list, text_message=email_body_text,
                        html_message=email_body_html)

        except IOError as e:
            logger.info('IOError'+ str(e))
            return ("IO ERROR")
        except Exception as e:
            logger.info("other error"+ str(e))
            return ("ERROR")
    return True


def create_download_pdf_auth(repo_url, userjson, email, main_tex="main.tex", options={}):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    file_full_path = ''
    new_main_tex = "main2.tex"

    user = User.User(userjson.get("username"), userjson.get("password"))
    github_token = user.get_attribute('github_token')
    if github_token is None or github_token == '':
        return("ERROR NO GITHUB TOKEN")

    try:
        repo_url = "https://{}:x-oauth-basic@{}".format(github_token, repo_url.split("://")[1])
    except:
        return("Invalid GIT Repository URL")

    store_petition(repo_url, RENDER_HASH, user.username)
    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'
    if email is None or email == "":
        email = user.username
    watermark = "Document generated for: " + email

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            timestamp = str(time.time())
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)
            if options != {}: #if there are special conditions to render
                # modify the original template:
                template = latex_jinja_env.get_template(filesdir +"/"+main_tex)
                renderer_template = template.render(**options)
                with open(filesdir + "/" + new_main_tex, "w") as f:  # saves tex_code to outpout file
                    f.write(renderer_template)
            else:
                new_main_tex = main_tex

            file_full_path = filesdir + "/" + new_main_tex.split(".")[0] + ".pdf"
            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            complete_hash = get_hash([timestamp, email], [run_git_rev_parse.decode('UTF-8')])
            run_latex_result = subprocess.call("texliveonfly --compiler=latex " + new_main_tex, shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("bibtex " + new_main_tex.split(".")[0], shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex " + new_main_tex, shell=True,
                                               cwd=filesdir)

            pointa = fitz.Point(AXIS_X, AXIS_Y)
            pointb = fitz.Point(AXIS_X_LOWER, AXIS_Y)
            document = fitz.open(file_full_path)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize=WATERMARK_SIZE, fontname=WATERMARK_FONT,
                                rotate=WATERMARK_ROTATION)
                page.insertText(pointb, text="DocId: " + complete_hash, fontsize=WATERMARK_SIZE,
                                fontname=WATERMARK_FONT, rotate=WATERMARK_ROTATION)
            document.save(file_full_path, incremental=1)
            document.close()

            pdffile = open(file_full_path, 'rb').read()
            return(pdffile)

        except IOError as e:
            logger.info('IOError'+ str(e))
            return("IO ERROR")
        except Exception as e:
            logger.info("other error"+ str(e))
            return("ERROR")


def create_download_pdf_google(pdf_url, user_credentials, email):
    file_full_path = file_full_path64 = ""
    file_tittle = "document.pdf"
    pdf_id = get_id_from_url(pdf_url)
    if pdf_id is False:
        return False

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **user_credentials
    )

    timestamp = str(time.time())
    watermark = "Document generated for: " + email
    complete_hash = get_hash([timestamp, email], [pdf_id])

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            file_full_path64 = tmpdir + "/" + pdf_id + ".base64"
            file_full_path = tmpdir + "/" + pdf_id + ".pdf"
            drive = googleapiclient.discovery.build(
                conf.API_SERVICE_NAME, conf.API_VERSION, credentials=credentials)

            request = drive.files().export_media(fileId=pdf_id,
                                                 mimeType='application/pdf')
            metadata = drive.files().get(fileId=pdf_id).execute()
            file_tittle = metadata.get("title").strip(" ") + ".pdf"

            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request, chunksize=conf.CHUNKSIZE)
            done = False
            while done is False:
                status, done = downloader.next_chunk()


            with open(file_full_path, 'wb') as mypdf:
                mypdf.write(fh.getvalue())

            pointa = fitz.Point(AXIS_X, AXIS_Y_GOOGLE)
            pointb = fitz.Point(AXIS_X_LOWER, AXIS_Y_GOOGLE)
            document = fitz.open(file_full_path)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize=WATERMARK_SIZE, fontname=WATERMARK_FONT,
                                rotate=WATERMARK_ROTATION, morph=(pointa, FLIP_MATRIX))
                page.insertText(pointb, text="DocId: " + complete_hash, fontsize=WATERMARK_SIZE,
                                fontname=WATERMARK_FONT, rotate=WATERMARK_ROTATION, morph=(pointb, FLIP_MATRIX))
            document.save(file_full_path, incremental=1)
            document.close()

            pdffile = open(file_full_path, 'rb').read()

            return pdffile, complete_hash, file_tittle

        except IOError as e:
            logger.info('google render IOError' + str(e))
            return False, False, False
        except Exception as e:
            logger.info("other error google render" + str(e))
            return False, False, False


def create_download_pdf(repo_url, email, main_tex="main.tex", options={}):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    file_tittle = "document.pdf"
    file_full_path = ''
    complete_hash = ""
    new_main_tex = "main2.tex"
    if email is None or email== "":
        return False, False

    store_petition(repo_url, RENDER_HASH, email)
    watermark = "Document generated for: "+ email

    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            timestamp = str(time.time())
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            file_tittle = repo_name.strip(" ") + ".pdf"
            filesdir = os.path.join(tmpdir, repo_name)
            if options != {}: #if there are special conditions to render
                # modify the original template:
                template = latex_jinja_env.get_template(filesdir +"/"+main_tex)
                renderer_template = template.render(**options)
                with open(filesdir + "/" + new_main_tex, "w") as f:  # saves tex_code to outpout file
                    f.write(renderer_template)
            else:
                new_main_tex = main_tex

            file_full_path = filesdir + "/" + new_main_tex.split(".")[0] + ".pdf"
            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            complete_hash = get_hash([timestamp, email], [run_git_rev_parse.decode('UTF-8')])
            run_latex_result = subprocess.call("texliveonfly --compiler=latex " + new_main_tex, shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("bibtex " + new_main_tex.split(".")[0], shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex " + new_main_tex, shell=True,
                                               cwd=filesdir)

            pointa = fitz.Point(AXIS_X, AXIS_Y)
            pointb = fitz.Point(AXIS_X_LOWER, AXIS_Y)
            document = fitz.open(file_full_path)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize=WATERMARK_SIZE, fontname=WATERMARK_FONT,
                                rotate=WATERMARK_ROTATION)
                page.insertText(pointb, text="DocId: " + complete_hash, fontsize=WATERMARK_SIZE,
                                fontname=WATERMARK_FONT, rotate=WATERMARK_ROTATION)
            document.save(file_full_path, incremental=1)
            document.close()

            pdffile = open(file_full_path, 'rb').read()
            return pdffile, complete_hash, file_tittle

        except IOError as e:
            logger.info('IOError'+ str(e))
            return False, False, False
        except Exception as e:
            logger.info("other error"+ str(e))
            return False, False, False


def render_pdf_base64_latex(repo_url, main_tex= "main.tex", options={}):
    '''clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
    repo_name = ''
    file_full_path = ''
    new_main_tex = "main.tex"
    store_petition(repo_url, RENDER_NOHASH, "")

    clone = 'git clone ' + repo_url
    rev_parse = 'git rev-parse master'

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            run_latex_result = subprocess.check_output(clone, shell=True, cwd=tmpdir)
            repo_name = os.listdir(tmpdir)[0]
            filesdir = os.path.join(tmpdir, repo_name)
            if options != {}: #if there are special conditions to render
                # modify the original template:
                template = latex_jinja_env.get_template(filesdir +"/"+main_tex)
                renderer_template = template.render(**options)
                with open(filesdir + "/" + new_main_tex, "w") as f:  # saves tex_code to outpout file
                    f.write(renderer_template)
            else:
                new_main_tex = main_tex

            run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
            run_latex_result = subprocess.call("texliveonfly --compiler=latex " + new_main_tex, shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("bibtex " + new_main_tex.split(".")[0], shell=True,
                                               cwd=filesdir)
            run_latex_result = subprocess.call("texliveonfly --compiler=pdflatex " + new_main_tex, shell=True,
                                               cwd=filesdir)

            file_full_path = filesdir + "/" + new_main_tex.split(".")[0] + ".pdf"
            file_full_path64 = filesdir + "/" + new_main_tex.split(".")[0] + ".base64"
            with open(file_full_path, 'rb') as f:
                with open(file_full_path64, 'wb') as ftemp:
                    # write in a new file the base64
                    ftemp.write(base64.b64encode(f.read()))

            pdffile = open(file_full_path64, 'r').read()

            return (pdffile)

        except IOError as e:
            logger.info('IOError'+ str(e))
            return False
        except Exception as e:
            logger.info("other error"+ str(e))
            return False


def render_pdf_base64_google(pdf_url, user_credentials):
    file_full_path= file_full_path64 = ""

    pdf_id = get_id_from_url(pdf_url)
    if pdf_id is False:
        return False

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **user_credentials
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        file_full_path64 = tmpdir + "/" + pdf_id + ".base64"
        file_full_path = tmpdir + "/" + pdf_id + ".pdf"
        drive = googleapiclient.discovery.build(
            conf.API_SERVICE_NAME, conf.API_VERSION, credentials=credentials)

        request = drive.files().export_media(fileId=pdf_id,
                                             mimeType='application/pdf')

        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request, chunksize=conf.CHUNKSIZE)
        done = False
        while done is False:
            status, done = downloader.next_chunk()

        with open(file_full_path64, 'wb') as ftemp:
            # write in a new file the base64
            ftemp.write(base64.b64encode(fh.getvalue()))

        pdffile = open(file_full_path64, 'r').read()

        return (pdffile)


def create_dynamic_endpoint(document_dict, userjson):
    base_url= conf.BASE_URL
    PDF_VIEW_URL = '/api/v1/pdf/'
    try:
        user = User.User()
        user = user.find_by_attr("username", userjson.get("username"))
        if user is not False:
            nda = Document.Document()
            document_dict.update({"org_id": user.org_id})
            nda.set_attributes(document_dict)
            nda_id = nda.create_nda()
            if nda_id is not False:
                return base_url+PDF_VIEW_URL+nda_id

    except Exception as e:
        logger.info("error creating nda"+ str(e))
        return False

    logger.info("Information not valid creating nda")
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

class RegisterUserByEmail(BaseHandler):
    '''receives a payload with the user data and stores it on the bd'''


    def post(self):
        VERIFICATION_HTML = "<h3>Hello,</h3>\
                <p>Click <a href='{}'>HERE</a> to verify your email.</p>\
                <p>Best regards,</p>"
        try:
            ADMIN_URL = conf.BASE_URL + BASE_PATH+"validate_email?code="
            email = self.get_argument('email', "")

            if is_valid_email(email):
                user = User.User(email)
                if user.find() is False:
                    code = user.get_validation_code()
                    if code is False:
                        self.write(json.dumps({"error": "user"}))
                    try:

                        html_text = VERIFICATION_HTML.format(ADMIN_URL + code)
                        mymail = Mailer(username=SMTP_USER, password=SMTP_PASS, host=SMTP_ADDRESS, port=SMTP_PORT)
                        mymail.send(subject="Documentation", email_from=SMTP_EMAIL, emails_to=[email],
                            html_message=html_text)
                        self.write(json.dumps({"response": "email sent"}))
                    except Exception as e:
                        logger.info("sending email: "+str(e))
                        self.write(json.dumps({"error": "email"}))
                else:
                    self.write(json.dumps({"error": "user"}))

            else:
                self.write(json.dumps({"error": "email"}))

        except:
            logger.info("registering user: " + str(e))
            self.write(json.dumps({"error": "email"}))

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

class WebhookConfirm(BaseHandler):
    '''receives a payload with the user data and stores it on the bd'''
    def post(self):
        try:
            user = User.User()
            json_data = json.loads(self.request.body.decode('utf-8'))
            if json_data.get("token") is not None and json_data.get("user_email") is not None :
                user = user.find_by_attr("username", json_data.get("user_email"))
                if json_data.get("token") == conf.PAY_TOKEN and json_data.get("payment_status") is not None:
                    user.set_attributes({"has_paid": json_data.get("payment_status")})
                    user.update()

                    self.write_json({"response": "ok"}, 200)
                else:
                    error = "error on token"
                    logger.info(error)
                    self.write_json({"error": error}, 401)
        except:
            error= "error getting response"
            logger.error(error)
            self.write_json({"error": error}, 500)

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

            if json_data.get("email_body_html") is None or json_data.get("email_body_html") == "":
                email_body_html = DEFAULT_HTML_TEXT
            else:
                email_body_html = json_data.get("email_body_html")

            if json_data.get("email_body_text") is None or json_data.get("email_body_text") == "":
                email_body_text = ""
            else:
                email_body_text = json_data.get("email_body_text")

            if json_data.get("options") is None or json_data.get("options") == {}  or json_data.get("options") == "":
                options = {}
            else:
                options = json_data.get("options")


            userjson = ast.literal_eval(userid)
            result = create_email_pdf_auth(json_data.get("remote_url"),userjson, email, email_body_html, main_tex,  email_body_text, options)
            if result:
                self.write(json.dumps({"response": "done"}))
            else:
                self.write(json.dumps({"response": "Error"}))

        except Exception as e:
            logger.info("error on clone"+ str(e))
            self.write(json.dumps({"response": "Error"}))


class RenderUrl(BaseHandler):
    '''recives a get with the github repository url as parameters and renders it to PDF with clone_repo'''

    def get(self):
        try:
            repo_url = self.get_argument('url', "")
            main_tex = self.get_argument('maintex', "main.tex")
            email = self.get_argument('email', "")
            email_body_html = self.get_argument('email_body_html', DEFAULT_HTML_TEXT)
            email_body_text =self.get_argument('email_body_text', "")
            options = json.loads(self.get_argument('options', "{}"))

            result = create_email_pdf(repo_url, email,email_body_html, main_tex,email_body_text, options)
            if result:
                self.write(json.dumps({"response":"done"}))
            else:
                self.write(json.dumps({"response": "Error"}))


        except Exception as e:
            logger.info("error on clone"+ str(e))
            self.write(json.dumps({"response": "Error"}))

@jwtauth
class PostWpNda(BaseHandler):
    '''recives a post with the github repository url and renders it to PDF with clone_repo'''

    def post(self, userid):
        new_dict = {}

        json_data = json.loads(self.request.body.decode('utf-8'))
        try:
            if json_data.get("wp_url") is None or json_data.get("wp_url") == "":
                self.write(json.dumps({"response": "Error, White paper url not found"}))
            else:
                new_dict["wp_url"]= json_data.get("wp_url")

            if json_data.get("wp_main_tex") is not None and json_data.get("wp_main_tex") != "":
                new_dict["main_tex"] = json_data.get("wp_main_tex")
            else:
                new_dict["main_tex"] = "main.tex"

            if json_data.get("pdf_url") is not None and json_data.get("pdf_url") != "":
                new_dict["nda_url"] = json_data.get("pdf_url")

            userjson = ast.literal_eval(userid)
            result = create_dynamic_endpoint(new_dict, userjson)
            if result is not False:
                self.write(json.dumps({"endpoint": result}))
            else:
                self.write(json.dumps({"response": "Error"}))

        except Exception as e:
            logger.info("error creating endpoint"+ str(e))
            self.write(json.dumps({"response": "Error"}))


"""No autentication endpoint"""
class HelloWorld(BaseHandler):
    def get(self):
        self.write(json.dumps({"response": "hello world"}))

    def post(self):
        self.write(json.dumps({"response": "hello world"}))



