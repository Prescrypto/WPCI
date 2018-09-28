from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from flask_oauthlib.client import OAuth
from tornado.wsgi import WSGIContainer, WSGIAdapter
import logging
import base64
import tempfile
import config as conf
from models.mongoManager import ManageDB
from handlers.routes import jwtauth, validate_token, render_pdf_base64, create_download_pdf
from handlers.emailHandler import Mailer
from models import User, Nda
from handlers.WSHandler import *
from utils import *

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')


DEFAULT_HTML_TEXT = "<h3>Hello,</h3>\
        <p>You will find the documentation you requested attached, thank you very much for your interest.</p>\
        <p>Best regards,</p>"


app = Flask(__name__)
app.debug = True
app.secret_key = conf.SECRET
oauth = OAuth(app)

DEFAULT_LOGO_PATH = "static/images/default_logo.base64"
TIMEZONE = "America/Mexico_City"

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
                    logger.info("no github session token")
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
    return redirect(url_for('index', error=error))

@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')

@app.route('/api/v1/pdf/<id>', methods=['GET', 'POST'])
def show_pdf(id):
    error = None
    message = None
    pdffile = ""
    nda_logo = ""
    ATTACH_CONTENT_TYPE = 'octet-stream'
    mymail = Mailer(username=conf.SMTP_USER, password=conf.SMTP_PASS, server=conf.SMTP_ADDRESS, port=conf.SMTP_PORT)

    if request.method == 'GET':
        try:
            nda = Nda.Nda()
            thisnda = nda.find_by_id(id)
            if thisnda is not None:
                if thisnda.pdf_url is not None and thisnda.pdf_url != "":
                    render_options = {"companyname": thisnda.org_name, "companytype": thisnda.org_type,
                                      "companyaddress": thisnda.org_address}
                    pdffile = render_pdf_base64(thisnda.pdf_url, "main.tex", render_options)
                    return render_template('pdf_form.html', id=id, error=error, pdffile=pdffile, org_name=thisnda.org_name)
                else:
                    error="No valid Pdf url found"
            else:
                error = 'ID not found'

        except Exception as e:
            logger.info(e)
            error= "Couldn't render the PDF on the page"

    if request.method == 'POST':
        attachments_list = []
        NDA_FILE_NAME = "ndacontract.pdf"
        WPCI_FILE_NAME = "whitepaper.pdf"

        try:
            signer_email = request.form.get("signer_email")
            signer_name = request.form.get("signer_name")
            if signer_email is None or signer_email == "":
                error = "Error, you must enter a valid email"
                return render_template('pdf_form.html', id=id, error=error)
            if signer_name is None or signer_name == "":
                error = "Error, you must enter a valid Name"
                return render_template('pdf_form.html', id=id, error=error)

            nda_file_base64 = str(request.form.get("nda_file"))
            nda = Nda.Nda()
            thisnda = nda.find_by_id(id)
            wp_main_tex = "main.tex"
            if thisnda is not None:
                if thisnda.wp_main_tex is not None and thisnda.wp_main_tex != "":
                    wp_main_tex = thisnda.wp_main_tex
                if thisnda.wp_url is not None and thisnda.wp_url != "":
                    '''here we create a temporary directory to store the files while the function sends it by email'''
                    with tempfile.TemporaryDirectory() as tmpdir:
                        wpci_file_path = os.path.join(tmpdir, WPCI_FILE_NAME)
                        nda_file_path = os.path.join(tmpdir, NDA_FILE_NAME)
                        try:
                            wpci_result = create_download_pdf(thisnda.wp_url, signer_email, wp_main_tex)

                            if wpci_result is False:
                                logger.info("Error rendering the white paper")
                                error = "Error rendering the white paper"
                                return render_template('pdf_form.html', id=id, error=error)

                            with open(wpci_file_path, 'wb') as ftemp:
                                ftemp.write(wpci_result)

                            owner_hash = get_hash([thisnda.org_name])
                            client_hash = get_hash([signer_email])
                            if thisnda.nda_logo is None:
                                nda_logo = open(DEFAULT_LOGO_PATH, 'r').read()
                            else:
                                nda_logo = thisnda.nda_logo

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
                                    "title": thisnda.org_name + " contract",
                                    "file_name": NDA_FILE_NAME,
                                    "logo": nda_logo
                                }
                            }

                            nda_result = get_nda(crypto_sign_payload)
                            if nda_result is not False:
                                # if the request returned a nda pdf file correctly then store it as pdf
                                with open(nda_file_path, 'wb') as ftemp:
                                    ftemp.write(nda_result)

                            else:
                                logger.info("failed loading nda")
                                error = "failed loading nda"
                                return render_template('pdf_form.html', id=id, error=error)
                            #this is the payload for the white paper file
                            wpci_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                                   file_path=wpci_file_path,
                                                   filename=WPCI_FILE_NAME)
                            attachments_list.append(wpci_attachment)
                            #this is the payload for the nda file
                            nda_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                                   file_path=nda_file_path,
                                                   filename=NDA_FILE_NAME)
                            attachments_list.append(nda_attachment)

                            mymail.send(subject="Documentation", email_from=conf.SMTP_EMAIL,
                                        emails_to=[signer_email], emails_bcc=[conf.ADMIN_EMAIL],
                                        attachments_list=attachments_list, text_message = "",
                                        html_message=DEFAULT_HTML_TEXT)

                            message = "successfully sent your files "

                        except Exception as e: #except from temp directory
                            logger.info(e)
                            error = "Error sending the email"
                            return render_template('pdf_form.html', id=id, error=error)

                else:
                    logger.info("No valid wp Pdf url found")
                    error = "No valid wp Pdf url found"
                    return render_template('pdf_form.html', id=id, error=error)

            else:
                logger.info('ID not found')
                error = 'ID not found'
                return render_template('pdf_form.html', id=id, error=error)

        except Exception as e: #function except
            logger.info(e)
            error = "there was an error on your files"
            return render_template('pdf_form.html', id=id, error=error)


    return render_template('pdf_form.html', id=id, error=error, message=message)




