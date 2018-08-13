import os
TOKEN = os.environ.get('GITHUB_TOKEN', '')
headers = {'Content-Type' : 'application/json' } #get the content in json format
headers["Authorization"] = "token " + TOKEN #authentication for github
GITHUB_API_URL = "https://api.github.com/"
SECRET = os.environ.get('SECRET', '')
MONGO_URI= os.environ.get('MONGODB_URI', '')
SMTP_PASS='AsliNhKzIulaVuNOz80nHhyKNWPRXcfGE6aR38qCxooz' #os.environ.get('SMTP_PASS', '')
SMTP_EMAIL= 'hola@prescrypto.com' #os.environ.get('SMTP_EMAIL', '')
SMTP_USER= 'AKIAJU4ARVBFK6MOQWNA'#os.environ.get('SMTP_USER', '')
SMTP_ADDRESS= 'email-smtp.us-west-2.amazonaws.com' #os.environ.get('SMTP_ADDRESS', '')
SMTP_PORT= 587 #os.environ.get('SMTP_PORT', '')
CONSUMER_KEY = os.environ.get('CONSUMER_KEY', '')
CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET', '')
GITHUB_OAUTH_URI = os.environ.get('GITHUB_OAUTH_URI', '') #https://github.com/login/oauth/ 
