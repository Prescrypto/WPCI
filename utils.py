import time
import hashlib
import re

from models import User
from models.mongoManager import ManageDB
from jira import JIRA
import config as conf
import logging

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')


ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

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