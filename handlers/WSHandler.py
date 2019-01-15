#python
import json
import os
import sys
from requests.auth import HTTPBasicAuth
import requests
import base64
import logging
import datetime


#internal
import config as conf
from utils import CryptoTools, ordered_data


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

            # if there is a token in the payload then request the pdf
            headers["Authorization"] = "Bearer " + token_json_result.get("access_token")
            sign_result = requests.post(url=URL + SIGN_URL, json=payload, headers=headers)

            return sign_result.content
    except Exception as e:
        logger.info("requesting cryptosign pdf "+ str(e))

    return False


def post_to_rexchain(rexchain_data, user):
    rex_endpoint = "api/v1/rx-endpoint/"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        crypto_tools = CryptoTools()
        org_priv_key = crypto_tools.import_RSA_string(user.priv_key)
        org_pub_key = crypto_tools.import_RSA_string(user.pub_key)

        rexchain_data.update({
            "public_key": crypto_tools.savify_key(org_pub_key).decode('utf-8'),
            "timestamp": timestamp
        })

        rexchain_data["params"] = ordered_data(rexchain_data["params"])
        rexchain_data["signatures"] = ordered_data(rexchain_data["signatures"])
        data_sorted = ordered_data(rexchain_data)
        json_data_sorted = json.dumps(data_sorted, separators=(',', ':'))

        signature = crypto_tools.sign(
            json_data_sorted.encode('utf-8'),
            org_priv_key
        ).decode('utf-8')

        rexchain_payload = {
            "data": data_sorted,
            "signature": signature
        }

        rexchain_result = requests.post(url = conf.REXCHAIN_URL + rex_endpoint, json = rexchain_payload,
            headers = conf.headers)

        print(rexchain_result.content)


    except Exception as e:
        logger.info("requesting rexchain response "+ str(e))

