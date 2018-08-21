import json
import os
import sys
import config as conf
from requests.auth import HTTPBasicAuth
import requests
import base64

from tornado.httpclient import AsyncHTTPClient, HTTPClient, HTTPRequest


headers = conf.headers
GIT_BASE_URI = conf.GITHUB_API_URL

def get_nda(payload):
    print("getting nda")
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

    token_result = requests.post(url= URL+TOKEN_URL,data=jsondata, headers=tokenheaders, auth=auth)
    token_json_result = json.loads(token_result.content)
    if token_json_result.get("access_token"):
        #if there is a token in the payload then request the pdf
        headers["Authorization"] = "Bearer " + token_json_result.get("access_token")
        sign_result = requests.post(url=URL + SIGN_URL, json=payload, headers=headers)
        return sign_result.content

    return False

