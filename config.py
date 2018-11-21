import os
TIMEZONE = "America/Mexico_City"
TOKEN = os.environ.get('GITHUB_TOKEN', '')
headers = {'Content-Type' : 'application/json' } #get the content in json format
GITHUB_API_URL = "https://api.github.com/"
SECRET = os.environ.get('SECRET', '')
MONGO_URI= os.environ.get('MONGODB_URI', '')
SMTP_PASS=os.environ.get('SMTP_PASS', '')
SMTP_EMAIL= os.environ.get('SMTP_EMAIL', '')
ADMIN_EMAIL= os.environ.get('ADMIN_EMAIL', '')
SMTP_USER= os.environ.get('SMTP_USER', '')
SMTP_ADDRESS= os.environ.get('SMTP_ADDRESS', '')
SMTP_PORT= os.environ.get('SMTP_PORT', '')
CONSUMER_KEY = os.environ.get('CONSUMER_KEY', '')
CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET', '')
GITHUB_OAUTH_URI = os.environ.get('GITHUB_OAUTH_URI', '') #https://github.com/login/oauth/
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:7000')
CRYPTO_ID = os.environ.get('CRYPTO_ID', '')
CRYPTO_SECRET = os.environ.get('CRYPTO_SECRET', '')
CRYPTO_USERNAME = os.environ.get('CRYPTO_USERNAME', '')
CRYPTO_PASS = os.environ.get('CRYPTO_PASS', '')
CRYPTO_SIGN_URL = os.environ.get('CRYPTO_SIGN_URL', '')
# Settings JIRA
JIRA_URL = os.environ['JIRA_URL']
JIRA_USER = os.environ['JIRA_USER']
JIRA_PASSWORD = os.environ['JIRA_PASSWORD']
PRODUCTION = os.environ['PRODUCTION']
PAY_URL = os.environ['PAY_URL']
PAY_PLAN_ID = os.environ['PAY_PLAN_ID']
PAY_TOKEN = os.environ.get('PAY_TOKEN', '')
GOOGLE_TOKEN_URI = "https://www.googleapis.com/oauth2/v3/token"
GOOGLE_CLIENT_ID=os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_PROJECT_ID = os.environ.get('GOOGLE_PROJECT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

SCOPES = ['https://www.googleapis.com/auth/drive',
                  'https://www.googleapis.com/auth/drive.file',
                  'https://www.googleapis.com/auth/drive.readonly']
CLIENT_SECRETS_FILE = "client_secret.json"
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'
# Number of times to retry failed downloads.
NUM_RETRIES = 5
# Number of bytes to send/receive in each request.
CHUNKSIZE = 2 * 1024 * 1024
