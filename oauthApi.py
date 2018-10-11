from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from werkzeug.utils import secure_filename
from flask_oauthlib.client import OAuth
from tornado.wsgi import WSGIContainer, WSGIAdapter
import logging
import base64
import tempfile
import subprocess
from tornado.template import Loader
import config as conf
from models.mongoManager import ManageDB
from handlers.routes import jwtauth, validate_token, render_pdf_base64, create_download_pdf
from handlers.emailHandler import Mailer
from models import User, Nda, Document
from handlers.WSHandler import *
from utils import *

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

#SMTP VARIABLES
SMTP_PASS = conf.SMTP_PASS
SMTP_USER = conf.SMTP_USER
SMTP_EMAIL = conf.SMTP_EMAIL
SMTP_ADDRESS = conf.SMTP_ADDRESS
SMTP_PORT = conf.SMTP_PORT
SENDER_NAME = "Andrea from Wpci"

UPLOAD_FOLDER = os.path.join("/static/images")
LANGUAGE = "en"

BASE_PATH = "/docs/"
PDF_URL = conf.BASE_URL + BASE_PATH +"pdf/"
ADMIN_URL = conf.BASE_URL + BASE_PATH + "validate_email?code="

DEFAULT_HTML_TEXT = "<h3>Hello,</h3>\
        <p>You will find the documentation you requested attached, thank you very much for your interest.</p>\
        <p>Best regards,</p>"


VERIFICATION_HTML = "<h1>Complete your WPCI registration</h1>\
                <p>You are receiving this email because you requested an account to try wpci</p>\
               <p>Click <a href='{}'>{}</a> to verify your email.</p>\
               <p>Best regards,</p>"

NOTIFICATION_HTML = "<h3>Hello,</h3>\
               <p>The email {} downloaded your document with id: {} </p>\
               <p>Best regards,</p>"


app = Flask(__name__)
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
    access_token_url= conf.GITHUB_OAUTH_URI +'access_token',
    authorize_url= conf.GITHUB_OAUTH_URI +'authorize'
)

@app.route(BASE_PATH+'index')
def index():
    error = ''
    username = ''
    step_2 = False
    step_3 = False

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

        return render_template('index.html', error=error, step_2 = step_2, step_3 = step_3)


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
                    mymail.send(subject="Just a few steps more", email_from=sender_format.format(SENDER_NAME, conf.SMTP_EMAIL),
                                emails_to=[username], html_message=html_text)
                    return redirect(url_for('register_success'))

                except Exception as e:
                    logger.info("sending email: " + str(e))
                    error= "Couldn't send verification code, please try again."
            else:
                error= "This user already exists, please login."
                logger.info(error)

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
                    mymail.send(subject="Just a few steps more", email_from=sender_format.format(SENDER_NAME, conf.SMTP_EMAIL),
                                emails_to=[email], html_message=html_text)
                    return redirect(url_for('register_success'))

                except Exception as e:
                    logger.info("sending email: " + str(e))
                    error = "Couldn't send verification code, please try again."
            else:
                error = "This user already exists, please login."
                logger.info(error)

    return render_template('register.html', error=error)


@app.route(BASE_PATH +'register_org', methods=['GET', 'POST'])
def register_org():
    error=''
    username=''
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

        if request.form['org_name'] and request.form['org_type'] and \
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


    return render_template('view_docs.html', error=error, document_list = document_list, doc_len=doc_len, base_url = PDF_URL, success=success)

@app.route(BASE_PATH+'edit_docs', methods=['GET', 'POST'])
def edit_docs():
    error=""
    user = User.User()
    if 'user' in session:
        username = session['user']['username']
        # we get all the user data by the username
        user = user.find_by_attr("username", username)
    else:
        logger.info("The user is not logued in")
        return redirect(url_for('login'))

    return render_template('edit_docs.html', error=error)

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
    if has_paid == "":
        has_paid = True
    else:
        has_paid = False

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

        nda = Document.Document()
        thisnda = nda.find_by_nda_id(id)
        if thisnda is not None:
            doc = thisnda

        has_paid = getattr(user, "has_paid", False)

    except Exception as e:
        logger.error(str(e))
        render_template('analytics.html', id=id, error=error)


    return render_template('analytics.html', id = id, error=error, doc = doc, has_paid = has_paid,
                           pay_url="{}{}?email={}&plan_id={}".format(conf.PAY_URL,EXTERNAL_PAY,user.username, conf.PAY_PLAN_ID))

@app.route(BASE_PATH+'documents/<type>', methods=['GET', 'POST'])
def documents(type):
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
        NDA_NOT_EMPTY = False
        WP_NOT_EMPTY = False
        if request.form['wp_name']:
            try:
                id_property = getattr(user, "org_id", False)
                name_property = getattr(user, "org_name", False)
                if id_property is False or name_property is False:
                    error= "There is no organization information"
                    logger.info(error)
                    return render_template('documents.html', type=type, error=error, org_name=error)

                doc = Document.Document(user.org_id)
                data= request.form.to_dict()

                if data.get("main_tex") is None or data.get("main_tex") == "":
                    data["main_tex"] = "main.tex"

                if data.get("nda_url") is not None and data.get("nda_url") != "":
                    NDA_NOT_EMPTY = True
                if data.get("wp_url") is not None and data.get("wp_url") != "":
                    WP_NOT_EMPTY = True

                '''Check if the permissions are enough for the repositories if the 
                user is authenticated then use a different url with github authentication'''
                github_token = user.github_token
                if github_token is None or github_token == '':
                    logger.info("github token is not set")
                    try:
                        GITHUB_URL = "github.com"
                        if NDA_NOT_EMPTY and GITHUB_URL in data.get("nda_url").split("/"):
                            data["nda_url"] = "git://{}".format(data.get("nda_url").split("://")[1])
                        if WP_NOT_EMPTY and GITHUB_URL in data.get("wp_url").split("/"):
                            data["wp_url"] = "git://{}".format(data.get("wp_url").split("://")[1])
                    except:
                        error ="error getting correct url on git for public access"
                        logger.info(error)
                        return render_template('documents.html', type=type, error=error)

                else:
                    try:
                        if NDA_NOT_EMPTY:
                            data["nda_url"] = "https://{}:x-oauth-basic@{}".format(github_token, data.get("nda_url").split("://")[1])
                        if WP_NOT_EMPTY:
                            data["wp_url"] = "https://{}:x-oauth-basic@{}".format(github_token, data.get("wp_url").split("://")[1])
                    except:
                        error = "error getting correct url on git for private access"
                        logger.info(error)
                        return render_template('documents.html', type=type, error=error)

                try:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        if NDA_NOT_EMPTY:
                            clone = 'git clone ' + data["nda_url"]
                            subprocess.check_output(clone, shell=True, cwd=tmpdir)
                        if WP_NOT_EMPTY:
                            clone = 'git clone ' + data["wp_url"]
                            subprocess.check_output(clone, shell=True, cwd=tmpdir)
                except:
                    error= "You don't have permissions to clone the repository provided"
                    logger.info(error)
                    return render_template('documents.html', type=type, error=error, git_error = "error")


                doc.set_attributes(data)
                nda_url = doc.create_nda()
                if not nda_url:
                    error= "couldn't create the nda"
                    logger.info(error)
                    return render_template('documents.html', type=type, error=error)

                success= "Succesfully created your document, the Id is: "+ nda_url
                return redirect(url_for('view_docs', success = success))

            except Exception as e:
                logger.info("documents post " + str(e))
                error = 'Error updating the information'

        else:
            error = 'Invalid Values. Please try again.'
            logger.info(error)

        return render_template('documents.html', type=type, error=error)

    if request.method == 'GET':
        return render_template('documents.html', type=type, error=error)



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

@app.route('/api/v1/pdf/<id>', methods=['GET', 'POST'])
def redir_pdf(id):
    return redirect(url_for('show_pdf', id=id))

@app.route(BASE_PATH+'pdf/<id>', methods=['GET', 'POST'])
def show_pdf(id):
    error = None
    message = None
    pdffile = ""
    org_logo = ""
    ATTACH_CONTENT_TYPE = 'octet-stream'
    FIRST_SESSION = False
    mymail = Mailer(username=conf.SMTP_USER, password=conf.SMTP_PASS, host=conf.SMTP_ADDRESS, port=conf.SMTP_PORT)

    if request.method == 'GET':
        try:
            if 'first_session' in session:
                FIRST_SESSION = False

            else:
                session['first_session'] = True
                FIRST_SESSION = True

            nda = Document.Document()
            thisnda = nda.find_by_nda_id(id)
            if thisnda is not None:
                if thisnda.nda_url is None or thisnda.nda_url == "":
                    if thisnda.wp_url is None or thisnda.wp_url == "":
                        error = "No valid Pdf url found"
                        logger.info(error)
                        return render_template('pdf_form.html', id=id, error=error)
                    else:
                        pdf_url = thisnda.wp_url
                else:
                    pdf_url = thisnda.nda_url
                user = User.User()
                user = user.find_by_attr("org_id", thisnda.org_id)
                render_options = {"companyname": user.org_name, "companytype": user.org_type,
                                  "companyaddress": user.org_address}
                pdffile = render_pdf_base64(pdf_url, "main.tex", render_options)
                if not pdffile:
                    error = "Error rendering the pdf with the nda url"
                    logger.info(error)
                    return render_template('pdf_form.html', id=id, error=error)

                temp_view_count = thisnda.get_attribute("view_count")
                thisnda.set_attributes({"view_count": int(temp_view_count) + 1})
                thisnda.update()

                return render_template('pdf_form.html', id=id, error=error, pdffile=pdffile, org_name=user.org_name, tour_js=FIRST_SESSION)

            else:
                error = 'ID not found'
                logger.info(error)
                return render_template('pdf_form.html', id=id, error=error)

        except Exception as e:
            logger.info("rendering pdf nda "+str(e))
            error= "Couldn't render the PDF on the page"
            return render_template('pdf_form.html', id=id, error=error)

    if request.method == 'POST':
        attachments_list = []
        NDA_FILE_NAME = "ndacontract.pdf"
        WPCI_FILE_NAME = "whitepaper.pdf"
        render_nda_only = render_wp_only = False

        try:
            signer_email = request.form.get("signer_email")
            signer_name = request.form.get("signer_name")
            if signer_email is None or signer_email == "":
                error = "Error, you must enter a valid email"
                logger.info(error)
                return render_template('pdf_form.html', id=id, error=error)
            if signer_name is None or signer_name == "":
                error = "Error, you must enter a valid Name"
                logger.info(error)
                return render_template('pdf_form.html', id=id, error=error)

            nda_file_base64 = str(request.form.get("nda_file"))
            nda = Document.Document()
            thisnda = nda.find_by_nda_id(id)

            if thisnda is not None and thisnda.org_id is not None:
                if thisnda.nda_url is None or thisnda.nda_url == "" :
                    render_wp_only = True

                if thisnda.wp_url is None or thisnda.wp_url == "":
                    render_nda_only = True


                user = User.User()
                user = user.find_by_attr("org_id", thisnda.org_id)
                '''here we create a temporary directory to store the files while the function sends it by email'''
                with tempfile.TemporaryDirectory() as tmpdir:

                    client_hash = get_hash([signer_email])
                    if user.org_logo is None:
                        org_logo = open(DEFAULT_LOGO_PATH, 'r').read()
                    else:
                        org_logo = user.org_logo

                    try:
                        if render_wp_only or render_nda_only is False:
                            wpci_file_path = os.path.join(tmpdir, WPCI_FILE_NAME)
                            wpci_result = create_download_pdf(thisnda.wp_url, signer_email, thisnda.main_tex)

                            if wpci_result is False:
                                error = "Error rendering the white paper"
                                logger.info(error)
                                return render_template('pdf_form.html', id=id, error=error)

                            with open(wpci_file_path, 'wb') as ftemp:
                                ftemp.write(wpci_result)

                            # this is the payload for the white paper file
                            wpci_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                                   file_path=wpci_file_path,
                                                   filename=WPCI_FILE_NAME)
                            attachments_list.append(wpci_attachment)

                        if render_nda_only or render_wp_only is False:
                            nda_file_path = os.path.join(tmpdir, NDA_FILE_NAME)

                            crypto_sign_payload = {
                                "timezone": TIMEZONE,
                                "pdf": nda_file_base64,
                                "signatures": [
                                    {
                                        "hash": client_hash,
                                        "email": signer_email,
                                        "name": signer_name
                                    }],
                                "params": {
                                    "locale": LANGUAGE,
                                    "title": user.org_name + " contract",
                                    "file_name": NDA_FILE_NAME,
                                    "logo": org_logo
                                }
                            }

                            nda_result = get_nda(crypto_sign_payload)

                            if nda_result is not False:
                                # if the request returned a nda pdf file correctly then store it as pdf
                                with open(nda_file_path, 'wb') as ftemp:
                                    ftemp.write(nda_result)

                            else:
                                error = "failed loading nda"
                                logger.info(error)
                                return render_template('pdf_form.html', id=id, error=error)


                            #this is the payload for the nda file
                            nda_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                                   file_path=nda_file_path,
                                                   filename=NDA_FILE_NAME)
                            attachments_list.append(nda_attachment)

                        #send the email with the result attachments
                        sender_format = "{} <{}>"
                        loader = Loader("templates/email")
                        button = loader.load("cta_button.html")

                        mymail.send(subject="Documentation", email_from=sender_format.format(user.org_name, conf.SMTP_EMAIL),
                                    emails_to=[signer_email],
                                    attachments_list=attachments_list,
                                    html_message=DEFAULT_HTML_TEXT+ button.generate().decode("utf-8"))

                        html_text = NOTIFICATION_HTML.format(signer_email,thisnda.nda_id)
                        mymail.send(subject="Document Downloaded", email_from=sender_format.format(user.org_name, conf.SMTP_EMAIL),
                                    emails_to=[user.org_email],html_message=html_text)

                        message = "successfully sent your files "

                        temp_down_count = thisnda.get_attribute("down_count")
                        thisnda.set_attributes({"down_count": int(temp_down_count) + 1})
                        thisnda.update()

                    except Exception as e: #except from temp directory
                        logger.info("sending the email with the documents "+ str(e))
                        error = "Error sending the email"
                        return render_template('pdf_form.html', id=id, error=error)

            else:
                error = 'ID not found'
                logger.info(error)
                return render_template('pdf_form.html', id=id, error=error)

        except Exception as e: #function except
            logger.info("error loading the files "+str(e))
            error = "there was an error on your files"
            return render_template('pdf_form.html', id=id, error=error)


    return render_template('pdf_form.html', id=id, error=error, message=message)




