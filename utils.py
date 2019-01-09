#python
import time
import hashlib
import re
import logging
import os
import tempfile
import base64

#external app
from jira import JIRA

#web app
from tornado.template import Loader
from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from tornado.web import  os, asynchronous
from tornado import gen

#internal
import config as conf
from models import User
from handlers.routes import create_download_pdf_google, create_download_pdf
from handlers.WSHandler import get_nda
from handlers.emailHandler import Mailer

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')


ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
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


def get_hash(strings_list, hashes_list=[]):
    payload = ""
    hashed_payload = None
    for string in strings_list:
        payload = payload + hashlib.sha256(string.encode('utf-8')).hexdigest()
    for hash in hashes_list:
        payload = payload+hash
    hash_object = hashlib.sha256(payload.encode('utf-8'))
    hashed_payload = hash_object.hexdigest()

    return hashed_payload

def is_valid_email(email):
  return bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", email))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_jira_issue(summary, description, comment="", project_key="PROP", task_type="Task"):
    # Method to create JIRA issue
    try:
        authed_jira = JIRA(server=conf.JIRA_URL,basic_auth=(conf.JIRA_USER, conf.JIRA_PASSWORD))
        issue_dict = {
            'project': {'key': project_key},
            'description': description,
            'issuetype': {'name': task_type},
            'summary' : summary,
        }
        if not conf.PRODUCTION:
            issue_dict["project"] = {'key' : 'DEVPROP'}
            issue_dict["summary"] = '[DEV] ' + summary

        new_issue = authed_jira.create_issue(fields=issue_dict)
        # add comments
        if comment != "":
            authed_jira.add_comment(new_issue, comment)

    except Exception as e:
        logger.error( "Error al Crear Issue en JIRA : %s." % e)

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def get_id_from_url(pdf_url):
    pdf_id = ""
    # https://docs.google.com/document/d/1kvcIofihvrWq3o5KekoqVX6gZeTVP8oCm3oX-UnjMK8/edit?usp=sharing
    if pdf_url.find("/d/") > -1:
        temp_url = pdf_url.split("/d/")[1]
        pdf_id = temp_url.split("/edit")[0]
    elif pdf_url.find("id=") > -1:
        pdf_id = pdf_url.split("=")[1]
    else:
        logger.info("Document id not found in url")
        return False

    return pdf_id

def generate_credentials():
    loader = Loader("static/auth")
    my_cred_file = loader.load("google_secret_format.txt")
    result = my_cred_file.generate().decode("utf-8") % (conf.GOOGLE_CLIENT_ID, conf.GOOGLE_PROJECT_ID, conf.GOOGLE_CLIENT_SECRET, conf.BASE_URL+"/docs/")
    with open(conf.CLIENT_SECRETS_FILE, "w") as cred_json:
        cred_json.write(result)

#@gen.engine
def render_and_send_docs(user, signer_email, signer_name, thisnda, nda_file_base64, google_credentials_info, render_wp_only, render_nda_only):
    attachments_list = []
    NDA_FILE_NAME = "contract.pdf"
    WPCI_FILE_NAME = "whitepaper.pdf"
    doc_id = ""
    org_logo = ""
    ATTACH_CONTENT_TYPE = 'octet-stream'
    mymail = Mailer(username=conf.SMTP_USER, password=conf.SMTP_PASS, host=conf.SMTP_ADDRESS, port=conf.SMTP_PORT)

    '''here we create a temporary directory to store the files while the function sends it by email'''
    with tempfile.TemporaryDirectory() as tmpdir:

        client_hash = get_hash([signer_email])
        if user.org_logo is None or user.org_logo == "_":
            org_logo = open(DEFAULT_LOGO_PATH, 'r').read()
        else:
            org_logo = user.org_logo

        try:
            if render_nda_only is False:
                wpci_file_path = os.path.join(tmpdir, WPCI_FILE_NAME)

                doc_type = getattr(thisnda, "render", False)
                if doc_type is not False and doc_type == "google":
                    google_token = getattr(user, "google_token", False)
                    if google_token is not False:
                        wpci_result, complete_hash, WPCI_FILE_NAME = create_download_pdf_google(thisnda.wp_url,
                            google_credentials_info,signer_email)
                else:
                    wpci_result, complete_hash, WPCI_FILE_NAME = create_download_pdf(thisnda.wp_url,
                    signer_email,thisnda.main_tex)

                if wpci_result is False:
                    error = "Error rendering the white paper"
                    logger.info(error)
                    return render_template('pdf_form.html', id=doc_id, error=error)

                with open(wpci_file_path, 'wb') as ftemp:
                    ftemp.write(wpci_result)

                client_hash = complete_hash

                # this is the payload for the white paper file
                wpci_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                       file_path=wpci_file_path,
                                       filename=WPCI_FILE_NAME)
                attachments_list.append(wpci_attachment)

            if render_wp_only is False:
                nda_file_path = os.path.join(tmpdir, NDA_FILE_NAME)

                crypto_sign_payload = {
                    "pdf": nda_file_base64,
                    "timezone": TIMEZONE,
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
                    return render_template('pdf_form.html', id=doc_id, error=error)

                # this is the payload for the nda file
                nda_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                      file_path=nda_file_path,
                                      filename=NDA_FILE_NAME)
                attachments_list.append(nda_attachment)

            # send the email with the result attachments
            sender_format = "{} <{}>"
            loader = Loader("templates/email")
            button = loader.load("cta_button.html")
            notification_subject = "Your Document {} has been downloaded".format(thisnda.nda_id)
            analytics_link = "{}{}analytics/{}".format(conf.BASE_URL, BASE_PATH, thisnda.nda_id)

            mymail.send(subject="Documentation", email_from=sender_format.format(user.org_name, conf.SMTP_EMAIL),
                        emails_to=[signer_email],
                        attachments_list=attachments_list,
                        html_message=DEFAULT_HTML_TEXT + button.generate().decode("utf-8"))

            html_text = NOTIFICATION_HTML.format(signer_email, thisnda.nda_id, analytics_link, analytics_link)
            mymail.send(subject=notification_subject,
                        attachments_list=attachments_list,
                        email_from=sender_format.format("WPCI Admin", conf.SMTP_EMAIL),
                        emails_to=[user.org_email], html_message=html_text)


        except Exception as e:  # except from temp directory
            logger.info("sending the email with the documents " + str(e))
            error = "Error sending the email"
            return render_template('pdf_form.html', id=doc_id, error=error)
