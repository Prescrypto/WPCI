#python
import json
import os
import sys
from requests.auth import HTTPBasicAuth
import requests
import base64
import logging

#internal
import config as conf


from tornado.httpclient import AsyncHTTPClient, HTTPClient, HTTPRequest

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

headers = conf.headers
GIT_BASE_URI = conf.GITHUB_API_URL

def get_nda(payload):
    '''this function creates a new page dynamically by storing the payload posted into the data base'''
    URL= conf.CRYPTO_SIGN_URL
    SIGN_URL = 'api/v1/sign/'
    TOKEN_URL = 'oauth/token/'
    tokenheaders=  {'Content-Type' : 'application/x-www-form-urlencoded' }

    #request a token to cryptosign
    jsondata = {
        "grant_type": "password",
        "username": conf.CRYPTO_USERNAME,
        "password": conf.CRYPTO_PASS
    }

    auth = HTTPBasicAuth(conf.CRYPTO_ID, conf.CRYPTO_SECRET)

    try:
        token_result = requests.post(url= URL+TOKEN_URL,data=jsondata, headers=tokenheaders, auth=auth)
        token_json_result = json.loads(token_result.content)


        if token_json_result.get("access_token"):
            #if there is a token in the payload then request the pdf
            headers["Authorization"] = "Bearer " + token_json_result.get("access_token")
            sign_result = requests.post(url=URL + SIGN_URL, json=payload, headers=headers)

            return sign_result.content
    except Exception as e:
        logger.info("requesting cryptosign pdf "+ str(e))

    return False

