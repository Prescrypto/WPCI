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
from flask import Flask, redirect, url_for, session, request, jsonify, render_template

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
from models import User, Document, Link, signRecord, signerUser
from models.mongoManager import ManageDB
from handlers.emailHandler import Mailer
from handlers.WSHandler import *
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

#HTML EMAIL TEMPLATES
DEFAULT_HTML_TEXT = \
            "<h3>Hello,</h3>\
            <p>You will find the documentation you requested attached, thank you very much for your interest.</p>\
            <p>Best regards,</p>"
NOTIFICATION_HTML = \
            "<h3>Hi!</h3>\
            <p> {} has just downloaded the following document {}!</p>\
            <p>You can view detailed analytrics here: <a href='{}'>{}</a></p>\
            <p>Keep crushing it!</p>\
            <p>WPCI Admin</p>"
ATTACH_CONTENT_TYPE = 'octet-stream'

# S3 PATHS
FOLDER = "signed_files/"
BUCKET = "wpci-signed-docs"
S3_BASE_URL = "https://s3-us-west-2.amazonaws.com/"+BUCKET+"/"+FOLDER+"{}"

#SMTP VARIABLES
SMTP_PASS = conf.SMTP_PASS
SMTP_USER = conf.SMTP_USER
SMTP_EMAIL = conf.SMTP_EMAIL
SMTP_ADDRESS = conf.SMTP_ADDRESS
SMTP_PORT = conf.SMTP_PORT
SENDER_NAME = "Andrea WPCI"

#specific app variables
DEFAULT_LOGO_PATH = "static/images/default_logo.base64"
TIMEZONE = conf.TIMEZONE
LANGUAGE = "en"
AUTH_ERROR = {"error":"incorrect authentication"}

# Axis for the pdf header
AXIS_X = 15
AXIS_Y = 500
AXIS_Y_GOOGLE = 200
AXIS_X_LOWER = 28
AXIS_Y_LOWER = AXIS_Y + 11
PRESENTATION_OFFSET = 130
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
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=ONE_HOUR),
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
    '''this verifies a user and returns a token'''
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
    """ Handle Tornado JWT Auth """
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
    '''Gets the information from the payload and verifies if it is registered'''
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


def render_send_by_link_id(link_id, email, name, email_body_html="", email_body_text=""):
    """Download and render and then sign a document from google and send it by email"""
    b64_pdf_file = pdf_url = None
    doc_file_name = contract_file_name = ""
    render_nda_only = render_wp_only = False
    response = dict()
    try:
        doc_id = "_".join(link_id.split("_")[:-1])
    except Exception as e:
        logger.info("error obtaining link id")
        return False

    try:
        doc = Document.Document()
        thisdoc = doc.find_by_doc_id(doc_id)
        user = User.User()
        user = user.find_by_attr("org_id", thisdoc.org_id)

        google_credentials_info = {'token': user.google_token,
                                   'refresh_token': user.google_refresh_token,
                                   'token_uri': conf.GOOGLE_TOKEN_URI,
                                   'client_id': conf.GOOGLE_CLIENT_ID,
                                   'client_secret': conf.GOOGLE_CLIENT_SECRET,
                                   'scopes': conf.SCOPES}

        signer_user = signerUser.SignerUser(email, name)
        # create the signer user so it can generate their keys
        signer_user.create()
        timestamp_now = str(int(time.time()))

        if thisdoc.nda_url is None or thisdoc.nda_url == "":
            render_wp_only = True
            if thisdoc.wp_url is None or thisdoc.wp_url == "":
                error = "No valid Pdf url found"
                logger.info(error)
                return False
            else:
                # The file name is composed by the email of the user, the link id and the timestamp of the creation
                doc_file_name = "doc_{}_{}_{}.pdf".format(signer_user.email, link_id, timestamp_now)
                response.update({"s3_doc_url": S3_BASE_URL.format(doc_file_name)})
                pdf_url = thisdoc.wp_url
        else:
            pdf_url = thisdoc.nda_url
            contract_file_name = "contract_{}_{}_{}.pdf".format(signer_user.email, link_id, timestamp_now)
            response.update({"s3_contract_url": "{}{}view_sign_records/{}".format(conf.BASE_URL, BASE_PATH, link_id)})
            if thisdoc.wp_url is None or thisdoc.wp_url == "":
                render_nda_only = True
            else:
                doc_file_name = "doc_{}_{}_{}.pdf".format(signer_user.email, link_id, timestamp_now)
                response.update({"s3_doc_url": S3_BASE_URL.format(doc_file_name)})

        doc_type = getattr(thisdoc, "render", False)
        if doc_type is not False and doc_type == "google":
            google_token = getattr(user, "google_token", False)
            if google_token is not False:
                b64_pdf_file = render_pdf_base64_google(pdf_url, google_credentials_info)
        else:
            b64_pdf_file = render_pdf_base64_latex(pdf_url, "main.tex", {})

        if not b64_pdf_file:
            error = "Error rendering the pdf with the nda url"
            logger.info(error)
            return False

        thislink = Link.Link()
        thislink = thislink.find_by_link(link_id)
        temp_signed_count = thislink.signed_count
        thislink.signed_count = int(temp_signed_count) + 1
        thislink.status = "signed"
        thislink.update()

        # render and send the documents by email
        render_and_send_docs(user, thisdoc, b64_pdf_file, google_credentials_info, render_wp_only, render_nda_only,
                             signer_user, link_id, doc_file_name, contract_file_name, email_body_html, email_body_text)

        return response

    except Exception as e:
        logger.info("Checking document information {}".format(str(e)))
        return False


def create_email_pdf(repo_url, user_email, email_body_html, main_tex="main.tex", email_body_text="", options ={}):
    '''Clones a repo and renders the file received as main_tex and then signs it'''
    repo_name = ''
    file_full_path = ''
    attachments_list = []
    new_main_tex = "main2.tex"
    ATTACH_CONTENT_TYPE = 'octet-stream'
    mymail = Mailer(username=SMTP_USER, password=SMTP_PASS, host=SMTP_ADDRESS, port=SMTP_PORT)

    if user_email is None or user_email== "":
        return("NO EMAIL TO HASH")
    user_email = user_email.strip()

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
            mymail.send(subject="Documentation", email_from=SMTP_EMAIL,emails_to=[user_email],emails_bcc=[conf.ADMIN_EMAIL],
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
    '''Clones a repo and renders the file received as main_tex and then sends it to the user email (username)'''
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
    '''Clones a repo and renders the file received as main_tex with authentication'''
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
            if options != {}: # if there are special conditions to render
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
    '''Download and render and then sign a document from google'''
    file_full_path = file_full_path64 = ""
    file_tittle = "document.pdf"
    MORPH = None
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
            modified_date = metadata.get("modifiedDate")
            mime_type = metadata.get("mimeType")

            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request, chunksize=conf.CHUNKSIZE)
            done = False
            while done is False:
                status, done = downloader.next_chunk()


            with open(file_full_path, 'wb') as mypdf:
                mypdf.write(fh.getvalue())

            if mime_type == "application/vnd.google-apps.presentation":
                pointa = fitz.Point(AXIS_X, AXIS_Y- PRESENTATION_OFFSET)
                pointb = fitz.Point(AXIS_X_LOWER, AXIS_Y- PRESENTATION_OFFSET)
            elif mime_type == "application/vnd.google-apps.spreadsheet":
                pointa = fitz.Point(AXIS_X, AXIS_Y)
                pointb = fitz.Point(AXIS_X_LOWER, AXIS_Y)

            else:
                pointa = fitz.Point(AXIS_X, AXIS_Y_GOOGLE)
                pointb = fitz.Point(AXIS_X_LOWER, AXIS_Y_GOOGLE)
                MORPH = (pointb, FLIP_MATRIX)

            document = fitz.open(file_full_path)
            for page in document:
                page.insertText(pointa, text=watermark, fontsize=WATERMARK_SIZE, fontname=WATERMARK_FONT,
                                rotate=WATERMARK_ROTATION, morph=MORPH)
                page.insertText(pointb, text="DocId: " + complete_hash, fontsize=WATERMARK_SIZE,
                                fontname=WATERMARK_FONT, rotate=WATERMARK_ROTATION, morph=MORPH)
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
    '''Clones a repo and renders the file received as main_tex '''
    repo_name = ''
    file_tittle = "document.pdf"
    file_full_path = ''
    complete_hash = ""
    new_main_tex = "main2.tex"
    if email is None or email== "":
        return False, False

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
    '''Clones a repo and renders the file received as main_tex '''
    repo_name = ''
    file_full_path = ''
    new_main_tex = "main.tex"

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
    '''Download and render a pdf file from google'''
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


def create_link(doc_id):
    '''Create a new link for the document'''
    result = False
    try:
        mylink = Link.Link(doc_id)
        result = mylink.create_link()
        return result

    except Exception as e:
        logger.info("error creating the link" + str(e))
        return False


def delete_link(doc_id):
    '''Delete a previously created link'''
    result = False
    try:
        mylink = Link.Link(doc_id)
        result = mylink.delete_link()
        return True

    except Exception as e:
        logger.info("error deleting the link" + str(e))
        return False

def get_link_details(link_id):
    ''' Retrieves the status of a Document link (signed or unsigned)'''
    result = False
    try:
        mylink = Link.Link()
        result = mylink.find_by_link(link_id)
        return result

    except Exception as e:
        logger.info("error deleting the link" + str(e))
        return False

def get_document_details(doc_id):
    ''' Retrieves the status of a Document link (signed or unsigned)'''
    result = False
    try:
        doc = Document.Document()
        doc = doc.find_by_doc_id(doc_id)
        result = doc.__dict__
        result.pop("_id")
        result.pop("type")
        return result

    except Exception as e:
        logger.info("error getting document details " + str(e))
        return False


def get_b64_pdf(doc_id, userjson):
    '''Call the render function and retrive a base 64 pdf'''
    result = False
    try:
        user = User.User()
        user = user.find_by_attr("username", userjson.get("username"))
        doc = Document.Document()
        docs = doc.find_by_attr("doc_id", doc_id)
        if len(docs) > 0:
            doc = docs[0]
        else:
            return result
        doc_type = getattr(doc, "type", False)
        if doc_type is False:
            google_token = getattr(user, "google_token", False)
            if google_token is not False:
                user_credentials = {'token': user.google_token,
                          'refresh_token':user.google_refresh_token, 'token_uri': conf.GOOGLE_TOKEN_URI,
                          'client_id': conf.GOOGLE_CLIENT_ID,
                           'client_secret': conf.GOOGLE_CLIENT_SECRET,
                            'scopes': conf.SCOPES}
                bytes =  render_pdf_base64_google(doc.get("wp_url"), user_credentials)
            else:
                return result
        else:
            bytes =  render_pdf_base64_latex(doc.get("wp_url"))
        return bytes

    except Exception as e:
        logger.info("error rendering the document link " + str(e))

    return result


def create_dynamic_endpoint(document, userjson):
    '''This function retrives an URL formed by document ID and the Base url for the server'''
    base_url= conf.BASE_URL
    PDF_VIEW_URL = '/api/v1/pdf/'
    try:
        user = User.User()
        user = user.find_by_attr("username", userjson.get("username"))
        if user is not False:
            document.org_id = user.org_id
            doc_id = document.create_document()
            if doc_id is not False:
                return doc_id

    except Exception as e:
        logger.info("error creating doc" + str(e))
        return False

    logger.info("Information not valid creating doc")
    return False


def render_document(tmpdir, thisdoc, doc_file_name, user, google_credentials_info, signer_user, attachments_list):
    WPCI_FILE_NAME = "whitepaper.pdf"
    wpci_file_path = os.path.join(tmpdir, WPCI_FILE_NAME)
    wpci_result = False
    error = ""
    try:
        doc_type = getattr(thisdoc, "render", False)
        if doc_type is not False and doc_type == "google":
            google_token = getattr(user, "google_token", False)
            if google_token is not False:
                wpci_result, complete_hash, WPCI_FILE_NAME = create_download_pdf_google(
                    thisdoc.wp_url,
                    google_credentials_info,
                    signer_user.email)
        else:
            wpci_result, complete_hash, WPCI_FILE_NAME = create_download_pdf(
                thisdoc.wp_url,
                signer_user.email,
                thisdoc.main_tex)

        if not wpci_result:
            error = "Error rendering the document"
            logger.info(error)
            return attachments_list, error

        with open(wpci_file_path, 'wb') as temp_file:
            temp_file.write(wpci_result)

        uploaded_document_url = upload_to_s3(wpci_file_path, doc_file_name)
        signer_user.s3_doc_url = S3_BASE_URL.format(doc_file_name)
        signer_user.update()
        # this is the payload for the white paper file
        wpci_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                               file_path=wpci_file_path,
                               filename=WPCI_FILE_NAME)
        attachments_list.append(wpci_attachment)

    except Exception as e:
        logger.info("error rendering document: {}".format(str(e)))
        error = "error rendering document"
    finally:
        return attachments_list, error


def render_contract(user, tmpdir, nda_file_base64, contract_file_name,  signer_user, attachments_list, link_id):
    tx_id = error = ""
    NDA_FILE_NAME = "contract.pdf"
    try:
        crypto_tool = CryptoTools()
        if user.org_logo is None or user.org_logo == "":
            org_logo = open(DEFAULT_LOGO_PATH, 'r').read()
        else:
            org_logo = user.org_logo

        nda_file_path = os.path.join(tmpdir, NDA_FILE_NAME)
        sign_document_hash(signer_user, nda_file_base64)
        rsa_object = crypto_tool.import_RSA_string(signer_user.priv_key)
        pub_key_hex = crypto_tool.savify_key(rsa_object.publickey()).decode("utf-8")

        crypto_sign_payload = {
            "pdf": nda_file_base64,
            "timezone": TIMEZONE,
            "signature": signer_user.sign,
            "signatories": [
                {
                    "email": signer_user.email,
                    "name": signer_user.name,
                    "public_key": pub_key_hex
                }],
            "params": {
                "locale": LANGUAGE,
                "title": user.org_name + " contract",
                "file_name": NDA_FILE_NAME,
                "logo": org_logo,
            }
        }

        nda_result, sign_record = get_nda(crypto_sign_payload, signer_user)

        if not nda_result:
            error = "Failed loading contract"
            logger.info(error)
            return attachments_list, error

        # if the request returned a nda pdf file correctly then store it as pdf
        with open(nda_file_path, 'wb') as temp_file:
            temp_file.write(nda_result)

        uploaded_document_url = upload_to_s3(
            nda_file_path, contract_file_name
        )
        sign_record.s3_contract_url = S3_BASE_URL.format(contract_file_name)
        sign_record.link_id = link_id
        sign_record.update()
        # this is the payload for the nda file
        nda_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                              file_path=nda_file_path,
                              filename=NDA_FILE_NAME)
        attachments_list.append(nda_attachment)

    except Exception as e:
        logger.info("Error rendering contract: {}".format(str(e)))
    finally:
        return attachments_list, error


def render_and_send_docs(user, thisdoc, nda_file_base64, google_credentials_info, render_wp_only,
                         render_nda_only, signer_user, link_id, doc_file_name="", contract_file_name="",
                         email_body_html="", email_body_text=""):
    """Renders the documents and if needed send it to cryptosign and finally send it by email"""

    attachments_list = []
    doc_id = error = ""
    mymail = Mailer(username=conf.SMTP_USER, password=conf.SMTP_PASS, host=conf.SMTP_ADDRESS, port=conf.SMTP_PORT)

    # Here we create a temporary directory to store the files while the function sends it by email
    with tempfile.TemporaryDirectory() as tmp_dir:
        try:

            if render_nda_only is False:
                attachments_list, error = render_document(tmp_dir, thisdoc, doc_file_name, user, google_credentials_info,
                                                          signer_user, attachments_list)
            if render_wp_only is False:
                attachments_list, error = render_contract(user, tmp_dir, nda_file_base64,
                                                          contract_file_name, signer_user, attachments_list, link_id)

            if error != "":
                return render_template('pdf_form.html', id=doc_id, error=error)
            if not email_body_html:
                email_body_html = DEFAULT_HTML_TEXT

            # send the email with the result attachments
            sender_format = "{} <{}>"
            loader = Loader("templates/email")
            button = loader.load("cta_button.html")
            notification_subject = "Your Document {} has been downloaded".format(thisdoc.doc_id)
            analytics_link = "{}{}analytics/{}".format(conf.BASE_URL, BASE_PATH, thisdoc.doc_id)

            mymail.send(subject=thisdoc.wp_name, email_from=sender_format.format(user.org_name, conf.SMTP_EMAIL),
                        emails_to=[signer_user.email],
                        attachments_list=attachments_list,
                        html_message=email_body_html + button.generate().decode("utf-8"),
                        text_message=email_body_text)

            html_text = NOTIFICATION_HTML.format(signer_user.email, thisdoc.doc_id, analytics_link, analytics_link)
            mymail.send(subject=notification_subject,
                        attachments_list=attachments_list,
                        email_from=sender_format.format("WPCI Admin", conf.SMTP_EMAIL),
                        emails_to=[user.org_email], html_message=html_text,
                        text_message=email_body_text)

        except Exception as e:  # except from temp directory
            logger.info("sending the email with the documents " + str(e))
            error = "Error sending the email"
            return render_template('pdf_form.html', id=doc_id, error=error)


@jwtauth
class APINotFoundHandler(BaseHandler):
    '''If the endpoint doesn't exists then it will response with this code'''
    def options(self, *args, **kwargs):
        self.set_status(200)
        self.finish()


class AuthLoginHandler(BaseHandler):
    '''Receives the username and password to retrive a token'''
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
    """Receives a payload with the user data and stores it on the bd"""

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
    '''Receives a payload with the user data and stores it on the bd'''
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
    '''Receives a post with the github repository url and renders it to PDF with clone_repo'''

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
    '''Receives a get with the github repository url as parameters and renders it to PDF with clone_repo'''

    def get(self):
        try:
            link_id = self.get_argument('link_id', "")
            email = self.get_argument('email', "")
            name = self.get_argument('name', "")
            email_body_html = self.get_argument('email_body_html', DEFAULT_HTML_TEXT)
            email_body_text =self.get_argument('email_body_text', "")
            options = json.loads(self.get_argument('options', "{}"))

            result = render_send_by_link_id(link_id, email, name, email_body_html, email_body_text)
            if not result:
                self.write(json.dumps({"response": "Error"}))
            else:
                self.write(json.dumps(result))

        except Exception as e:
            logger.info("error on clone"+ str(e))
            self.write(json.dumps({"response": "Error"}))


@jwtauth
class PostWpNda(BaseHandler):
    '''Receives a post with the document url and responses with a document id '''

    def post(self, userid):
        json_data = json.loads(self.request.body.decode('utf-8'))
        try:
            doc = Document.Document()

            if not json_data.get("wp_url"):
                self.write(json.dumps({"response": "Error, White paper url not found"}))
            if not json_data.get("wp_name"):
                self.write(json.dumps({"response": "Error, White paper name not found"}))
            if not json_data.get("wp_main_tex"):
                json_data["main_tex"] = "main.tex"
            if not json_data.get("nda_url"):
                json_data["nda_url"] = ""
            if not json_data.get("email_body_html"):
                json_data["email_body_html"] = ""
            if not json_data.get("email_body_txt"):
                json_data["email_body_txt"] = ""

            doc.__dict__ = json_data
            userjson = ast.literal_eval(userid)

            result = create_dynamic_endpoint(doc, userjson)
            if result is not False:
                self.write(json.dumps({"doc_id": result}))
            else:
                self.write(json.dumps({"response": "Error"}))

        except Exception as e:
            logger.info("error creating endpoint" + str(e))
            self.write(json.dumps({"response": "Error"}))

    def get(self, userid):
        try:
            link_id = self.get_argument('link_id', "")
            email = self.get_argument('email', "")
            name = self.get_argument('name', "")
            email_body_html = self.get_argument('email_body_html', DEFAULT_HTML_TEXT)
            email_body_text = self.get_argument('email_body_text', "")
            options = json.loads(self.get_argument('options', "{}"))

            result = render_send_by_link_id(link_id, email, name, email_body_html, email_body_text)
            if not result:
                self.write(json.dumps({"response": "Error"}))
            else:
                self.write(json.dumps(result))

        except Exception as e:
            logger.info("error on clone" + str(e))
            self.write(json.dumps({"response": "Error"}))


class Links(BaseHandler):
    '''Get, create and delete a document link'''

    def get(self, link_id):
        if not validate_token(self.request.headers.get('Authorization')):
            self.write_json(AUTH_ERROR, 403)

        if link_id:
            result = get_link_details(link_id)
            if result is not False:
                result = result.__dict__
                result.pop("_id")

                #Replace the Link id for the full link url
                result["link"] = conf.BASE_URL +BASE_PATH+"pdf/" + result.pop("link")

                self.write_json(result, 200)
            else:
                self.write(json.dumps({"doc_status": "failed"}))

        else:
            self.write(json.dumps({"error": "not enough information to perform the action"}))

    def post(self, doc_id):
        if not validate_token(self.request.headers.get('Authorization')):
            self.write_json(AUTH_ERROR, 403)

        if doc_id:
            result = create_link(doc_id)
            if result is not False:
                result = result.__dict__
                result.pop("_id")

                # Replace the Link id for the full link url
                result["link"] = conf.BASE_URL + BASE_PATH + "pdf/" + result.pop("link")

                self.write_json(result, 200)
            else:
                self.write(json.dumps({"response": "failed link creation"}))

        else:
            self.write(json.dumps({"error": "not enough information to perform the action"}))

    def delete(self, link_id):
        if not validate_token(self.request.headers.get('Authorization')):
            self.write_json(AUTH_ERROR, 403)

        if link_id:
            result = delete_link(link_id)
            if result:
                self.write(json.dumps({"response": "link deleted"}))
            else:
                self.write(json.dumps({"response": "failed link creation"}))

        else:
            self.write(json.dumps({"error": "not enough information to perform the action"}))


@jwtauth
class RenderDocToPDF(BaseHandler):
    '''Receives a get with the id of the document and renders it to PDF with clone_repo'''

    def get(self, doc_id):
        '''Receives a document id and retrieves a json with a b64 pdf'''
        userjson = validate_token(self.request.headers.get('Authorization'))
        if not userjson:
            self.write_json(AUTH_ERROR, 403)

        if doc_id is not None and doc_id != "":
            result = get_b64_pdf(doc_id, userjson)
            if result is not False:
                self.write(json.dumps({"document": result}))
            else:
                self.write(json.dumps({"error": "failed"}))

        else:
            self.write(json.dumps({"error": "not enough information to perform the action"}))


class Documents(BaseHandler):
    '''Documents endpoint'''

    def get(self, doc_id):
        '''Receives a document id and retrieves all its parameters'''
        userjson = validate_token(self.request.headers.get('Authorization'))
        if not userjson:
            self.write_json(AUTH_ERROR, 403)

        if doc_id is not None and doc_id != "":
            result = get_document_details(doc_id)
            if result:
                self.write_json(result, 200)
            else:
                self.write(json.dumps({"error": "failed"}))

        else:
            self.write(json.dumps({"error": "not enough information to perform the action"}))

