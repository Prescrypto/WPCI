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
from tornado.web import os, asynchronous
import tornado
from tornado import gen
from tornado.ioloop import IOLoop
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
from models import User, Document, Link, signRecord, signerUser
from models.mongoManager import ManageDB
from handlers.emailHandler import Mailer
from handlers.WSHandler import *
from handlers.manageDocuments import manageDocuments
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
            <p>You can view detailed analytics here: <a href='{}'>{}</a></p>\
            <p>Keep crushing it!</p>\
            <p>WPCI Admin</p>"
ATTACH_CONTENT_TYPE = 'octet-stream'

# S3 PATHS
FOLDER = f"{conf.FOLDER_NAME}/"
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
        new_document = manageDocuments()
        new_document.get_document_by_doc_id(doc_id)
        if new_document.is_valid_document() and new_document.user_has_permission(user):
            # render and send the documents by email
            pdffile, complete_hash, file_tittle = new_document.render_document(main_tex="main.tex")
            pdf_b64 = new_document.convert_bytes_to_b64(pdffile)
            return pdf_b64

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
            username = json_data.get("username")
            if is_valid_email(username):
                user = User.User(username, json_data.get("password"))
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
            username = json_data.get("user_email")
            if json_data.get("token") is not None and username is not None:
                if is_valid_email(username):
                    user = user.find_by_attr("username", username)
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


class RenderUrl(BaseHandler):
    '''Receives a get with the github repository url as parameters and renders it to PDF with clone_repo'''

    def get(self):
        response = dict()
        try:
            timestamp_now = time.time()
            link_id = self.get_argument('link_id', "")
            email = self.get_argument('email', "")
            name = self.get_argument('name', "")
            email_body_html = self.get_argument('email_body_html', DEFAULT_HTML_TEXT)
            email_body_text =self.get_argument('email_body_text', "")
            options = json.loads(self.get_argument('options', "{}"))

            if is_valid_email(email):
                new_document = manageDocuments()
                new_document.get_document_by_link_id(link_id)
                if new_document.is_valid_document():
                    # The file name is composed by the email of the user,
                    # the link id and the timestamp of the creation
                    doc_file_name = F"doc_{email}_{new_document.link_id}_{timestamp_now}.pdf"
                    response.update(
                        {"s3_doc_url": F"{conf.BASE_URL}{BASE_PATH}view_sign_records/{link_id}"}
                    )

                    contract_file_name = F"contract_{email}_{new_document.link_id}_{timestamp_now}.pdf"
                    response.update(
                        {"s3_contract_url": F"{conf.BASE_URL}{BASE_PATH}view_sign_records/{link_id}"}
                    )

                    IOLoop.instance().add_callback(
                        callback=lambda:
                        new_document.render_and_send_all_documents(
                            email, name, email_body_html, timestamp_now, contract_file_name, doc_file_name,
                            contract_b64_file=None, main_tex="main.tex", email_body_text=email_body_text
                        )
                    )

            if not response:
                self.write(json.dumps({"response": "Error"}))
            else:
                self.write(json.dumps(response))

        except Exception as e:
            logger.info("error on clone"+ str(e))
            self.write(json.dumps({"response": "Error"}))


@jwtauth
class PostDocument(BaseHandler):
    '''Receives a post with the document url and responses with a document id '''

    def post(self, userid):

        try:
            json_data = json.loads(self.request.body.decode('utf-8'))
            if not json_data.get("doc_url"):
                self.write(json.dumps({"response": "Error, White paper url not found"}))
            if not json_data.get("doc_name"):
                self.write(json.dumps({"response": "Error, White paper name not found"}))
            if not json_data.get("doc_main_tex"):
                json_data["main_tex"] = "main.tex"
            if not json_data.get("contract_url"):
                json_data["contract_url"] = ""
            if not json_data.get("email_body_html"):
                json_data["email_body_html"] = ""
            if not json_data.get("email_body_txt"):
                json_data["email_body_txt"] = ""
            if not json_data.get("render"):
                json_data["render"] = "google"
            if not json_data.get("type"):
                json_data["type"] = conf.CONTRACT
            if not json_data.get("doc_description"):
                json_data["doc_description"] = " It is required to sign this before you can continue. Please\
                        read carefully and sign to continue."
            if not json_data.get("doc_getit_btn"):
                json_data["doc_getit_btn"] = "Sign to receive the document!"

            if json_data.get("type") == conf.CONTRACT and json_data.get("contract_url") == "":
                json_data["contract_url"] = json_data.get("doc_url")

            if json_data.get("type") == conf.NDA and (
                    json_data.get("contract_url") == "" or json_data.get("doc_url") == ""):
                self.write(json.dumps({"response": "Error, Couldn't create the document, no valid urls provided"}))

            doc = Document.Document()
            doc.__dict__ = json_data
            userjson = ast.literal_eval(userid)

            result = create_dynamic_endpoint(doc, userjson)
            if result is not False:
                self.write(json.dumps({"doc_id": result}))
            else:
                self.write(json.dumps({"response": "Error, Couldn't create the document"}))

        except Exception as e:
            logger.info("error creating endpoint" + str(e))
            self.write(json.dumps({"response": "Error the parameters are incorrect please send a valid json"}))

    def get(self, userid):
        result = None
        response = dict()
        contract_file_name = doc_file_name = "unknown.pdf"
        try:
            link_id = self.get_argument('link_id', "")
            email = self.get_argument('email', "")
            name = self.get_argument('name', "")
            email_body_html = self.get_argument('email_body_html', DEFAULT_HTML_TEXT)
            email_body_text = self.get_argument('email_body_text', "")
            options = json.loads(self.get_argument('options', "{}"))

            if is_valid_email(email):
                timestamp_now = str(time.time())
                try:
                    thislink = Link.Link()
                    thislink = thislink.find_by_link(link_id)
                    temp_signed_count = thislink.signed_count
                    thislink.signed_count = int(temp_signed_count) + 1

                    new_document = manageDocuments()
                    new_document.get_document_by_link_id(link_id)
                    if new_document.is_valid_document():
                        # render and send the documents by email
                        new_document.link_id = link_id

                        # The file name is composed by the email of the user,
                        # the link id and the timestamp of the creation
                        doc_file_name = F"doc_{email}_{new_document.link_id}_{timestamp_now}.pdf"
                        response.update(
                            {"s3_doc_url": F"{conf.BASE_URL}{BASE_PATH}view_sign_records/{link_id}"}
                        )

                        contract_file_name = F"contract_{email}_{new_document.link_id}_{timestamp_now}.pdf"
                        response.update(
                            {"s3_contract_url": F"{conf.BASE_URL}{BASE_PATH}view_sign_records/{link_id}"}
                        )

                        IOLoop.instance().add_callback(
                            callback=lambda:
                            new_document.render_and_send_all_documents(
                                email, name, email_body_html, timestamp_now, contract_file_name, doc_file_name,
                                contract_b64_file=None, main_tex="main.tex", email_body_text=email_body_text
                            )
                        )
                        thislink.status = "signed"
                        thislink.update()

                        self.write(json.dumps(response))

                    else:
                        self.write(json.dumps({"response": "Error, Couldn't find the document"}))
                except Exception as e:
                    logger.error(F"[ERROR PostDocument GET] {str(e)}")

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

