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


class WSHandler(object):
    http_client = AsyncHTTPClient()

    def get(self, url, data=None, headers=None):
        if data is not None:
            if isinstance(data, dict):
                data = json.dumps(data)
            if '?' in url:
                url += '&amp;%s' % data
            else:
                url += '?%s' % data
        return self.async_fetch(url, 'GET', headers=headers)

    def post(self, url, data, headers=None):
        if data is not None:
            if isinstance(data, dict):
                data = json.dumps(data)
        return self._fetch(url, 'POST', data, headers)

    def async_fetch(self, url):
        http_client = AsyncHTTPClient()
        response = yield http_client.fetch(url)
        self.on_response(url, response)

    def on_response(self, url, response):
        self.url_res[url] = response
        self.write(str(response) + "\n")
        self.flush()
        if not filter(lambda x: x is None, self.url_res.values()):
            self.finish()

def handle_response(res):
    if res.error:
        print (res.error)
    else:
        print ("success",res.body)

def get_nda(cryptosign_url, payload):
    URL= cryptosign_url
    SIGN_URL = 'api/v1/sign/'
    TOKEN_URL = 'oauth/token/'

    #request a token to cryptosign
    jsondata = {
        "grant_type": "password",
        "username": conf.CRYPTO_USERNAME,
        "password": conf.CRYPTO_PASS
    }

    auth = HTTPBasicAuth(conf.CRYPTO_ID, conf.CRYPTO_SECRET)

    token_result = requests.post(url= URL+TOKEN_URL,json=jsondata, headers=headers, auth=auth)
    token_json_result = json.loads(token_result.content)
    print(token_json_result)
    if token_json_result.get("access_token"):
        headers["Authorization"] = "Bearer " + token_json_result.get("access_token")
        sign_result = requests.post(url=URL + SIGN_URL, json=payload, headers=headers)
        json_result = json.loads(sign_result.content)
        return json_result.get("pdf")

    return False

