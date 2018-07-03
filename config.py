import os
TOKEN = os.environ.get('GITHUB_TOKEN', '')
headers = {'Content-Type' : 'application/json' } #get the content in json format
headers["Authorization"] = "token " + TOKEN #authentication for github
GITHUB_API_URL = "https://api.github.com/"
SECRET = os.environ.get('SECRET', '')
LISTEN_PORT = 5000
MONGO_URI= os.environ.get('MONGODB_URI', '')