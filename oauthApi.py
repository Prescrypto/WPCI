#python
import logging
import base64
import tempfile
import subprocess
import os
import io

#web app
from flask import Flask, redirect, url_for
from flask import session, request, jsonify, render_template
from werkzeug.utils import secure_filename
from flask_oauthlib.client import OAuth
from tornado.wsgi import WSGIContainer, WSGIAdapter
from flask_sslify import SSLify
from tornado import gen
from tornado.ioloop import IOLoop
from tornado.template import Loader

#google oauth
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.http import MediaIoBaseDownload

#github oauth
from oauth2client.client import OAuth2WebServerFlow

#internal
import config as conf
from models.mongoManager import ManageDB
from handlers.routes import *
from handlers.emailHandler import Mailer
from models import User, Document, signerUser, signRecord
from handlers.WSHandler import *
from utils import *


# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

# SMTP VARIABLES
SMTP_PASS = conf.SMTP_PASS
SMTP_USER = conf.SMTP_USER
SMTP_EMAIL = conf.SMTP_EMAIL
SMTP_ADDRESS = conf.SMTP_ADDRESS
SMTP_PORT = conf.SMTP_PORT
SENDER_NAME = "Andrea WPCI"

UPLOAD_FOLDER = os.path.join("/static/images")
LANGUAGE = "en"

BASE_PATH = "/docs/"
PDF_URL = conf.BASE_URL + BASE_PATH +"pdf/"
ADMIN_URL = conf.BASE_URL + BASE_PATH + "validate_email?code="

DEFAULT_HTML_TEXT = \
            "<h3>Hello,</h3>\
            <p>You will find the documentation you requested attached, thank you very much for your interest.</p>\
            <p>Best regards,</p>"

VERIFICATION_HTML = \
            "<h3>Hey,</h3>\
            <p>Thanks for your interest on WPCI, you're almost done. </p>\
            <p>Click HERE <a href='{}'>{}</a> to verify your email.</p>\
            <p>Best!</p>\
            <p>Andrea</p>"

NOTIFICATION_HTML = \
            "<h3>Hi!</h3>\
            <p> {} has just downloaded the following document {}!</p>\
            <p>You can view detailed analytics here: <a href='{}'>{}</a></p>\
            <p>Keep crushing it!</p>\
            <p>WPCI Admin</p>"


app = Flask(__name__)
sslify = SSLify(app)
app.debug = True
app.secret_key = conf.SECRET
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
oauth = OAuth(app)

DEFAULT_LOGO_PATH = "static/images/default_logo.base64"
TIMEZONE = conf.TIMEZONE

oauth_app = WSGIContainer(app)

github = oauth.remote_app(
    'github',
    consumer_key=conf.CONSUMER_KEY,
    consumer_secret=conf.CONSUMER_SECRET,
    request_token_params={'scope': 'repo'},
    base_url=conf.GITHUB_API_URL,
    request_token_url=None,
    access_token_method='POST',
    access_token_url=conf.GITHUB_OAUTH_URI + 'access_token',
    authorize_url=conf.GITHUB_OAUTH_URI + 'authorize'
)


@app.template_filter()
def get_s3_presigned_url(file_url):
    """Upload a file to the default S3 bucket"""
    try:
        file_name = file_url.split("/")[-1]
        # Get the service client.
        s3 = boto3.client('s3')
        # Generate the URL to get 'key-name' from 'bucket-name'
        document_url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={
                'Bucket': BUCKET,
                'Key': f'{FOLDER}{file_name.strip("/")}',
            },
            ExpiresIn=ONE_HOUR
        )
        return document_url
    except Exception as e:
        logger.info("Error getting presigned url: {}".format(str(e)))
        return "No Valid Url"


@app.template_filter('strftime')
def _jinja2_filter_datetime(date, fmt=None):
    date = datetime.datetime.fromtimestamp(int(date))
    native = date.replace(tzinfo=None)
    format='%b %d, %Y'
    return native.strftime(format)


@app.route(BASE_PATH+'index', methods=['GET', 'POST'])
def index():
    error = ''
    username = ''
    success = ""
    document_list = []
    step_2 = False
    step_3 = False
    doc_len = 0

    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    if request.method == 'GET':
        org_name = getattr(user, "org_name", False)
        if org_name is not False:
            step_2 = True
            docs = Document.Document()
            docs = docs.find_by_attr("org_id", user.org_id)
            if len(docs) > 0:
                step_3 = True

            docs = Document.Document()
            docs = docs.find_by_attr("org_id", user.org_id)
            document_list = docs
            doc_len = len(document_list)

    if request.method == 'POST':

        if request.form['org_name'] and request.form['org_email'] and request.form['org_address']:
            try:
                data = request.form.to_dict()
                try:
                    # check if the post request has the file part
                    if 'org_logo' not in request.files or request.files['org_logo'].filename == '':

                        if data["prev_logo"] is not None and data["prev_logo"] != "":
                            data["org_logo"] = data["prev_logo"]
                        else:
                            data["org_logo"] = open(DEFAULT_LOGO_PATH, 'r').read()
                    else:
                        file = request.files['org_logo']
                        if file and allowed_file(file.filename):
                            try:
                                data["org_logo"] = base64.b64encode(file.read()).decode('utf-8')
                            except Exception as e:
                                logger.info("loading b64 file " + str(e))
                                data["org_logo"] = open(DEFAULT_LOGO_PATH, 'r').read()


                except Exception as e:
                    logger.info("loading logo " + str(e))
                    error = "error loading the file"
                    return render_template('index.html', error=error,
                                           step_2=step_2, step_3=step_3,
                                           myuser=user)

                data.pop("prev_logo")
                data["google_refresh_token"] = ""
                user.set_attributes(data)
                user.update()

                return redirect(url_for('index'))

            except Exception as e:
                logger.info("registering org " + str(e))
                error = 'Error updating the information'

        else:
            error = 'Invalid Values. Please try again.'
            logger.info(error)

    return render_template('index.html', error=error, step_2=step_2,
                           step_3=step_3, myuser=user,
                           document_list=document_list, doc_len=doc_len,
                           success=success)


@app.route(BASE_PATH+'github_reg')
def github_reg():
    error =request.args.get('error')
    if 'user' in session:
        if 'github_token' in session:
            #me = github.get('user') #return jsonify(me.data) # we can get this information if there is a github_token at the session
            return render_template('github_reg.html', error=error)
        else:
            return render_template('github_reg.html', error= error)
    else:
        return redirect(url_for('login'))


@app.route(BASE_PATH+'login', methods=['GET', 'POST'])
def login():
    error=''
    if 'user' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if request.form['username'] and request.form['password']:
            user = User.User(request.form.get("username"), request.form.get("password"))
            if user.check():
                session["user"] = user.__dict__
                return redirect(url_for('index'))
            elif user.find():
                error = 'Wrong password or email. Please try again.'
            else:
                error = 'Invalid Credentials. Please register.'
                return redirect(url_for('register', error=error))

        else:
            error = 'Invalid Credentials. Please try again.'

    return render_template('login.html', error=error)


@app.route(BASE_PATH+'register', methods=['GET', 'POST'])
def register():
    error = None
    message = ""
    mymail = Mailer(username=SMTP_USER, password=SMTP_PASS, host=SMTP_ADDRESS, port=SMTP_PORT)
    sender_format = "{} <{}>"

    if request.method == 'POST':
        username = request.form['username']
        if username:
            msg = "New WPCI registration: {}".format(username)
            create_jira_issue(
                summary=msg,
                description="Nos han enviado su mail desde wpci try it button",
                comment="COOKIES: {}".format(request.cookies)
            )
            user = User.User(username)
            if user.find() is False:
                code = user.get_validation_code()
                if code is False:
                    error = "Couldn't get a verification code, please try again."
                    logger.info(error)
                    return render_template('register.html', error=error)

                try:
                    html_text = VERIFICATION_HTML.format(ADMIN_URL + code, ADMIN_URL + code)
                    mymail.send(subject="Just one more step", email_from=sender_format.format(SENDER_NAME, conf.SMTP_EMAIL),
                                emails_to=[username], html_message=html_text)
                    return redirect(url_for('register_success'))

                except Exception as e:
                    logger.info("sending email: " + str(e))
                    error= "Couldn't send verification code, please try again."
            else:
                error= "This user already exists, please reset your password or use a different email."
                logger.info(error) # TODO @val: change these to logger.error

    if request.method == 'GET':
        email = request.args.get('email', False)
        if email is not False:
            user = User.User(email)
            if user.find() is False:
                code = user.get_validation_code()
                if code is False:
                    error = "Couldn't get a verification code, please try again."
                    logger.info(error)
                    return render_template('register.html', error=error)

                try:
                    html_text = VERIFICATION_HTML.format(ADMIN_URL + code, ADMIN_URL + code)
                    mymail.send(subject="Just one more step", email_from=sender_format.format(SENDER_NAME, conf.SMTP_EMAIL),
                                emails_to=[email], html_message=html_text)
                    return redirect(url_for('register_success'))

                except Exception as e:
                    logger.info("sending email: " + str(e))
                    error = "Couldn't send verification code, please try again."
            else:
                error = "This user already exists, please reset your password or use a different email."
                logger.info(error)  # TODO @val: change these to logger.error

    return render_template('register.html', error=error)


@app.route(BASE_PATH +'register_org', methods=['GET', 'POST'])
def register_org():
    error = ''
    username = ''
    myuser = None

    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        #we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    if request.method == 'POST':

        if request.form['org_name'] and \
                request.form['org_email'] and request.form['org_address']:
            try:
                data = request.form.to_dict()
                try:
                    # check if the post request has the file part
                    if 'org_logo' not in request.files or request.files['org_logo'].filename == '':

                        if data["prev_logo"] is not None and data["prev_logo"] != "":
                            data["org_logo"] = data["prev_logo"]
                        else:
                            data["org_logo"] = open(DEFAULT_LOGO_PATH, 'r').read()
                    else:
                        file = request.files['org_logo']
                        if file and allowed_file(file.filename):
                            try:
                                data["org_logo"] = base64.b64encode(file.read()).decode('utf-8')
                            except Exception as e:
                                logger.info("loading b64 file "+str(e))
                                data["org_logo"] = open(DEFAULT_LOGO_PATH, 'r').read()


                except Exception as e:
                    logger.info("loading logo "+str(e))
                    error = "error loading the file"
                    return render_template('register_org.html', error=error, myuser=user)

                data.pop("prev_logo")
                data["google_refresh_token"] = ""
                user.set_attributes(data)
                user.update()

                return redirect(url_for('index'))

            except Exception as e:
                logger.info("registering org " + str(e))
                error = 'Error updating the information'

        else:
            error = 'Invalid Values. Please try again.'
            logger.info(error)

        return render_template('register_org.html', error=error, myuser=user)

    if request.method == 'GET':

        return render_template('register_org.html', error=error, myuser=user)


@app.route(BASE_PATH+'view_docs', methods=['GET', 'POST'])
def view_docs():
    document_list = []
    error = ''
    username = ''
    success = ''
    doc_len = 0
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    success = request.args.get('success', '')

    if request.method == 'GET' or request.method == 'POST':
        docs = Document.Document()
        docs = docs.find_by_attr("org_id", user.org_id)
        document_list = docs
        doc_len = len(document_list)

    return render_template('view_docs.html', error=error, document_list = document_list, doc_len=doc_len,
                           base_url = PDF_URL, success=success)


@app.route(BASE_PATH+'view_links/<doc_id>', methods=['GET', 'POST'])
def view_links(doc_id):
    link_list = []
    error = ''
    link_len = 0
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    if request.method == 'POST':
        result = create_link(doc_id)
        if not result:
            error = "There was a problem creating the new link"
        else:
            _link = Link.Link()
            link_list = _link.find_by_attr("doc_id", doc_id)

    if request.method == 'GET':
        links = Link.Link(doc_id)
        link_list = links.find_by_attr("doc_id", doc_id)

    return render_template('view_links.html', error=error, link_list=link_list, base_url=PDF_URL, doc_id=doc_id)


@app.route(BASE_PATH+'view_sign_records/<link_id>', methods=['GET', 'POST'])
def view_sign_records(link_id):
    document_list = []
    error = ''
    username = ''
    success = ''
    doc_len = 0
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    if request.method == 'GET' or request.method == 'POST':
        sign_record = signRecord.SignRecord()
        sign_records = sign_record.find_by_attr("link_id", link_id)
        if not sign_records:
            records_len = 0
        else:
            records_len = len(sign_records)

    return render_template('view_sign_records.html', error=error, sign_records=sign_records,
                           records_len=records_len, base_url=PDF_URL, link_id=link_id)


@app.route(BASE_PATH+'google_latex_docs', methods=['GET', 'POST'])
def google_latex_docs():
    error=""
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    return render_template('google_latex_docs.html', error=error, myuser=user)


@app.route(BASE_PATH+'edit_docs/<render>', methods=['GET', 'POST'])
def edit_docs(render):
    error=""
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
        google_token = getattr(user, "google_token", False)
        if render == "google" and not google_token:
            logger.info("no google auth")
            error = "google_error"

        elif render == "latex" and (user.github_token is None or user.github_token == "" or user.github_token == "null"):
            logger.info("no github auth")
            error = "github_error"

    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    return render_template('edit_docs.html', error=error, render=render, myuser=user)


@app.route(BASE_PATH+'success', methods=['GET'])
def register_success():
    error=""
    message = ""
    return render_template('register_success.html', error=error)


@app.route(BASE_PATH+'pay_success', methods=['GET'])
def pay_success():
    error=""
    message = ""
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    has_paid = getattr(user, "has_paid", False)
    if has_paid is False or has_paid == "subscription.payment_failed" or has_paid == "subscription.canceled":
        has_paid = False
    else:
        has_paid = True

    return render_template('pay_success.html', error=error, has_paid=has_paid)


@app.route(BASE_PATH+'analytics/<id>', methods=['GET', 'POST'])
def analytics(id):
    error=""
    doc = None
    has_paid = False
    EXTERNAL_PAY = "/extra_services/external_payment/"
    username = ''
    success = ''
    try:
        user = User.User()
        if 'user' in session:
            username = session['user']['username']
            # we get all the user data by the username
            user = user.find_by_attr("username", username)
        else:
            logger.info("The user is not logued in")
            return redirect(url_for('login'))

        doc = Document.Document()
        thisdoc = doc.find_by_doc_id(id)
        if thisdoc is not None:
            doc = thisdoc

        has_paid = getattr(user, "has_paid", False)

        if has_paid is False or has_paid == "subscription.payment_failed" or has_paid == "subscription.canceled":
            has_paid = False
        else:
            has_paid = True

    except Exception as e:
        logger.error(str(e))
        render_template('analytics.html', id=id, error=error)


    return render_template('analytics.html', id = id, error=error, doc = doc, has_paid = has_paid,
                           pay_url="{}{}?email={}&plan_id={}".format(conf.PAY_URL,EXTERNAL_PAY,user.username, conf.PAY_PLAN_ID))

@app.route(BASE_PATH+'documents/<type>/<render>', methods=['GET', 'POST'])
def documents(type, render):
    error=''
    username=''
    success = ''
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        #we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    if request.method == 'POST':
        CONTRACT_NOT_EMPTY = False
        DOC_NOT_EMPTY = False
        if request.form['doc_name']:
            try:
                id_property = getattr(user, "org_id", False)
                name_property = getattr(user, "org_name", False)
                if id_property is False or name_property is False:
                    error= "There is no organization information"
                    logger.info(error)
                    return render_template('documents.html', type=type, render=render, error=error, org_name=error)

                doc = Document.Document(user.org_id)
                data= request.form.to_dict()

                if data.get("main_tex") is None or data.get("main_tex") == "":
                    data["main_tex"] = "main.tex"

                if data.get("redirect_url") is None or data.get("redirect_url") == "":
                    data["redirect_url"] = ""

                if type == conf.CONTRACT:
                    '''This is a contract document without a white paper or other document'''
                    data["contract_url"] = data.get("doc_url")
                    data["doc_url"] = ""
                elif type == conf.DOCUMENT:
                    '''this is a document protected'''
                    data["contract_url"] = ""

                if data.get("contract_url") is not None and data.get("contract_url") != "":
                    CONTRACT_NOT_EMPTY = True
                    if data.get("doc_description") == "":
                        data["doc_description"] = user.org_name + " requires you to sign this before you can continue. Please\
                        read carefully and sign to continue."

                    if data.get("doc_getit_btn") == "":
                        data["doc_getit_btn"] = "I agree to the above terms in this NDA"
                else:
                    if data.get("doc_getit_btn") == "":
                        data["doc_getit_btn"] = "To get the complete document please check this box and fill the following fields"

                    if data.get("doc_description") == "":
                        data["doc_description"] = user.org_name + " Click on the Get it! button and enter your email so we can send you a copy of \
                        this document to your email."

                if data.get("doc_url") is not None and data.get("doc_url") != "":
                    DOC_NOT_EMPTY = True

                if render == "latex":
                    '''Check if the permissions are enough for the repositories if the 
                    user is authenticated then use a different url with github authentication'''
                    github_token = user.github_token
                    if github_token is None or github_token == '':
                        logger.info("github token is not set")
                        try:
                            GITHUB_URL = "github.com"
                            if CONTRACT_NOT_EMPTY and GITHUB_URL in data.get("contract_url").split("/"):
                                data["contract_url"] = "git://{}".format(data.get("contract_url").split("://")[1])
                            if DOC_NOT_EMPTY and GITHUB_URL in data.get("doc_url").split("/"):
                                data["doc_url"] = "git://{}".format(data.get("doc_url").split("://")[1])
                        except:
                            error ="error getting correct url on git for public access"
                            logger.info(error)
                            return render_template('documents.html', type=type, render=render, error=error)

                    else:
                        try:
                            if CONTRACT_NOT_EMPTY:
                                data["contract_url"] = "https://{}:x-oauth-basic@{}".format(github_token, data.get("contract_url").split("://")[1])
                            if DOC_NOT_EMPTY:
                                data["doc_url"] = "https://{}:x-oauth-basic@{}".format(github_token, data.get("doc_url").split("://")[1])
                        except:
                            error = "error getting correct url on git for private access"
                            logger.info(error)
                            return render_template('documents.html', type=type, render=render, error=error)

                    try:
                        with tempfile.TemporaryDirectory() as tmpdir:
                            if CONTRACT_NOT_EMPTY:
                                clone = 'git clone ' + data["contract_url"]
                                subprocess.check_output(clone, shell=True, cwd=tmpdir)

                            if DOC_NOT_EMPTY:
                                clone = 'git clone ' + data["doc_url"]
                                subprocess.check_output(clone, shell=True, cwd=tmpdir)

                    except Exception as e:
                        error= "You don't have permissions to clone the repository provided"
                        logger.info(str(e) + error)
                        return render_template('documents.html', type=type, render=render, error=error, url_error = "git_error")

                elif render == "google":
                    try:
                        google_token = getattr(user, "google_token", False)
                        if google_token is not False:
                            user_credentials = {'token': user.google_token,
                                'refresh_token':user.google_refresh_token, 'token_uri': conf.GOOGLE_TOKEN_URI,
                                'client_id': conf.GOOGLE_CLIENT_ID,
                                'client_secret': conf.GOOGLE_CLIENT_SECRET,
                                'scopes': conf.SCOPES}

                            credentials = google.oauth2.credentials.Credentials(
                                **user_credentials
                            )

                            pdf_id_contract = pdf_id_doc = True
                            if CONTRACT_NOT_EMPTY:
                                pdf_id_contract = get_id_from_url(data["contract_url"])
                            if DOC_NOT_EMPTY:
                                pdf_id_doc = get_id_from_url(data["doc_url"])

                            if pdf_id_contract is False or pdf_id_doc is False:
                                error = "error getting correct google document url please check it and try again"
                                logger.info(error)
                                return render_template('documents.html', type=type, render=render, error=error)

                            with tempfile.TemporaryDirectory() as tmpdir:
                                drive = googleapiclient.discovery.build(
                                    conf.API_SERVICE_NAME, conf.API_VERSION, credentials=credentials)

                                if CONTRACT_NOT_EMPTY:
                                    req_pdf = drive.files().export_media(fileId=pdf_id_contract,
                                                                         mimeType='application/pdf')
                                    fh = io.BytesIO()
                                    downloader = MediaIoBaseDownload(fh, req_pdf, chunksize=conf.CHUNKSIZE)
                                    done = False
                                    while done is False:
                                        status, done = downloader.next_chunk()

                                if DOC_NOT_EMPTY:
                                    req_pdf2 = drive.files().export_media(fileId=pdf_id_doc,
                                                                         mimeType='application/pdf')
                                    fh = io.BytesIO()
                                    downloader = MediaIoBaseDownload(fh, req_pdf2, chunksize=conf.CHUNKSIZE)
                                    done = False
                                    while done is False:
                                        status, done = downloader.next_chunk()

                        else:
                            error = "You don't have permissions for google docs"
                            return render_template('documents.html', type=type, render=render, error=error,
                                                   url_error="google_error")

                    except Exception as e:
                        logger.info("testing google doc: "+ str(e))
                        error = "You don't have permissions for google docs"
                        return render_template('documents.html', type=type, render=render, error=error,
                                               url_error="google_error")


                data["type"] = type
                data["render"] = render
                doc.set_attributes(data)
                doc_url = doc.create_document()
                if not doc_url:
                    error= "couldn't create the document"
                    logger.info(error)
                    return render_template('documents.html', type=type, render=render, error=error)

                success= "Succesfully created your document, the Id is: "+ doc_url
                return redirect(url_for('view_docs', success = success))

            except Exception as e:
                logger.info("documents post " + str(e))
                error = 'Error updating the information'

        else:
            error = 'Invalid Values. Please try again.'
            logger.info(error)

        return render_template('documents.html', type=type, render=render, error=error)

    if request.method == 'GET':
        return render_template('documents.html', type=type, render=render, error=error)


@app.route(BASE_PATH+'validate_email', methods=['GET', 'POST'])
def validate_email():
    error=''
    username = None
    if request.method == 'GET':
        code = request.args.get('code', None)
        if code:
            user = User.User()
            user = user.find_by_attr("code", code)

            if user is False:
                error = "This user is already authenticated or doesnt exists"
                return render_template('validate_email.html', error=error)
            else:
                username = user.get_attribute("username")

        else:
            error = 'Invalid code.'

    if request.method == 'POST':
        password = request.form['pass']
        username = request.form['username']
        if password and request.form['password']:
            user = User.User(username)
            user.validate_email(password)
            user = user.find_by_attr("username", username)
            session["user"] = {"username": user.username, "password": user.password}
            return redirect(url_for('index'))

    return render_template('validate_email.html', error=error, username=username)


@app.route(BASE_PATH+'gitlogin')
def gitlogin():
    return github.authorize(callback=url_for('authorized', _external=True))


@app.route(BASE_PATH+'gitlogout')
def logout():
    session.pop('user', None)
    session.pop('github_token', None)
    return redirect(url_for('github_reg'))


@app.route(BASE_PATH+'authorized')
def authorized():
    error = None
    resp = github.authorized_response()
    if resp is None or resp.get('access_token') is None:
        logger.info("no access token")
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
        logger.info("error getting Token")
        error= "error getting Token"
    return redirect(url_for('github_reg', error=error))


@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')


@app.route(BASE_PATH+'google_authorize')
def google_authorize():
    #we generate a credentials file with the env vars stored in this machine
    generate_credentials()

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      conf.CLIENT_SECRETS_FILE, scopes=conf.SCOPES)

    flow.redirect_uri = conf.BASE_URL + BASE_PATH + "oauth2callback"

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        approval_prompt='force',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='false')

    # Store the state so the callback can verify the auth server response.
    try:
        session['state'] = state
    except:
        logger.info("no state session")

    return redirect(authorization_url)


@app.route(BASE_PATH+'oauth2callback')
def oauth2callback():
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    try:
        state = session['state']
    except:
        logger.info("no state session")
        state = ""

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        conf.CLIENT_SECRETS_FILE, scopes=conf.SCOPES, state=state)
    flow.redirect_uri = conf.BASE_URL + BASE_PATH + "oauth2callback"

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    if session['credentials'].get("token") is not None and session['credentials'].get("token") != "null":
        user.google_token = session['credentials'].get("token")
    if session['credentials'].get("refresh_token") is not None and session['credentials'].get("refresh_token")!= "null":
        user.google_refresh_token = session['credentials'].get("refresh_token")
    user.update()

    return redirect(url_for('documents', render="google", type="nda"))


@app.route(BASE_PATH+'oauth2callback/google38fb6f671eadab58.html')
def oauthgoogle38fb6f671eadab58():
    return render_template('google38fb6f671eadab58.html')


@app.route(BASE_PATH+'termsofuse')
def termsofuse():
    return render_template('termsofuse.html')


@app.route(BASE_PATH+'privacypolicy')
def privacypolicy():
    return render_template('privacypolicy.html')


@app.route('/api/v1/pdf/<id>', methods=['GET', 'POST'])
def redir_pdf(id):
    return redirect(url_for('show_pdf', id=id))


@app.route('/', methods=['GET', 'POST'])
def redir_login():
    return redirect(url_for('login'))


@app.route(BASE_PATH+'pdf/<id>', methods=['GET', 'POST'])
def show_pdf(id):
    error = None
    doc_id = ""
    message = None
    is_contract = False
    b64_pdf_file = ""
    FIRST_SESSION = False

    try:
        doc_id = "_".join(id.split("_")[:-1])
    except Exception as e:
        logger.info("Trying to get id" + str(e))
        error = "No valid Pdf url found"
        return render_template('pdf_form.html', id=doc_id, error=error)

    if request.method == 'GET':
        try:

            new_document = ManageDocuments()
            new_document.get_document_by_link_id(id)
            if new_document.is_valid_document():
                # render and send the documents by email
                new_document.link_id = id

                if new_document.document.type == conf.CONTRACT or new_document.document.type == conf.NDA:
                    is_contract = True
                else:
                    is_contract = False

                if new_document.document.doc_url == "" and new_document.document.contract_url == "":
                    error = 'No Document url provided, unable to render the pdf'
                    logger.info(error)
                    return render_template('pdf_form.html', id=doc_id, error=error)

                # Render the pdf and convert it to b64
                pdf_file = new_document.render_main_document()
                b64_pdf_file = new_document.convert_bytes_to_b64(pdf_file)

                thislink = Link.Link()
                thislink = thislink.find_by_link(id)
                temp_view_count = thislink.view_count
                thislink.view_count = int(temp_view_count) + 1
                thislink.update()



                if 'first_session' not in session and b64_pdf_file:
                    FIRST_SESSION = True
                    session['first_session'] = True

                return render_template('pdf_form.html', id=doc_id, error=error, is_contract=is_contract,
                                       pdffile=b64_pdf_file, doc_description=new_document.document.doc_description,
                                       doc_getit_btn=new_document.document.doc_getit_btn, tour_js=FIRST_SESSION)

            else:
                error = 'ID not found'
                logger.info(error)
                return render_template('pdf_form.html', id=doc_id, error=error)

        except Exception as e:
            logger.info("rendering pdf nda "+str(e))
            error= "Couldn't render the PDF on the page"
            return render_template('pdf_form.html', id=id, error=error)

    if request.method == 'POST':
        email_body_html = DEFAULT_HTML_TEXT
        timestamp_now = str(int(time.time()))
        try:
            new_document = ManageDocuments()
            new_document.get_document_by_link_id(id)
            if new_document.is_valid_document():
                # render and send the documents by email
                new_document.link_id = id
                name = request.form.get("signer_name", False)
                email = request.form.get("signer_email", False)

                if not email:
                    error = "Error, you must enter a valid email"
                    logger.info(error)
                    return render_template('pdf_form.html', id=doc_id, error=error)
                if not name:
                    error = "Error, you must enter a valid Name"
                    logger.info(error)
                    return render_template('pdf_form.html', id=doc_id, error=error)

                contract_file_base64 = str(request.form.get("contract_file"))

                # generate document and contract file names by the email, link id and the current timestamp
                doc_file_name = doc_file_name = F"doc_{email}_{id}_{timestamp_now}.pdf"
                contract_file_name = F"contract_{email}_{id}_{timestamp_now}.pdf"
                # render and send the documents by email

                IOLoop.instance().add_callback(
                    callback=lambda:
                    new_document.render_and_send_all_documents(
                        email, name, email_body_html, timestamp_now, contract_file_name,
                        doc_file_name, contract_b64_file=contract_file_base64
                    )
                )

                message = "successfully sent your files "

                thislink = Link.Link()
                thislink = thislink.find_by_link(id)
                temp_signed_count = thislink.signed_count
                thislink.signed_count = int(temp_signed_count) + 1
                thislink.status = "signed"
                thislink.update()

                doc_redirect_url = getattr(new_document.document, "redirect_url", False)

                if doc_redirect_url and doc_redirect_url != "":
                    return redirect(doc_redirect_url)
            else:  # Not a valid document
                logger.info(F"error signing and rendering the files {str(e)}")
                error = "there was an error on your files"
                return render_template('pdf_form.html', id=doc_id, error=error)

        except Exception as e: #function except
            logger.info("error loading the files " + str(e))
            error = "there was an error on your files"
            return render_template('pdf_form.html', id=doc_id, error=error)

    return render_template('pdf_form.html', id=doc_id, error=error, message=message)
