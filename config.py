import os
TOKEN = os.environ.get('GITHUB_TOKEN', '')
headers = {'Content-Type' : 'application/json' } #get the content in json format
headers["Authorization"] = "token " + TOKEN #authentication for github
GITHUB_API_URL = "https://api.github.com/"
SECRET = os.environ.get('SECRET', '')
MONGO_URI= os.environ.get('MONGODB_URI', '')
SMTP_PASS= os.environ.get('SMTP_PASS', '')
SMTP_EMAIL= os.environ.get('SMTP_EMAIL', '')
SMTP_USER= os.environ.get('SMTP_USER', '')
SMTP_ADDRESS= os.environ.get('SMTP_ADDRESS', '')
SMTP_PORT= os.environ.get('SMTP_PORT', '')
CONSUMER_KEY = os.environ.get('CONSUMER_KEY', '')
CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET', '')
GITHUB_OAUTH_URI = os.environ.get('GITHUB_OAUTH_URI', '') #https://github.com/login/oauth/ 
