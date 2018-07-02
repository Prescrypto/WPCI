import json
import os
import config as conf

from tornado.httpclient import AsyncHTTPClient
from tornado.ioloop import IOLoop

headers = conf.headers
GIT_BASE_URI = conf.GITHUB_API_URL
AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")#configure the Httpclient as a curlAsyncHttpClient

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
        #print(url, response)
        self.write(str(response) + "\n")
        self.flush()
        if not filter(lambda x: x is None, self.url_res.values()):
            self.finish()

def handle_response(res):
    if res.error:
        print (res.error)
    else:
        print ("success",res.body)

def get_repo_pages():
    repo_url = 'repos/Prescrypto/cryptosign_whitepaper/contents/README.md'
    URL= GIT_BASE_URI + repo_url
    http_client = AsyncHTTPClient()
    # Asynchronous request for contet
    bodydict = {}
    bodydict.update({'username': ''})
    bodydict.update({'password': ''})
    headers['Accept'] = 'application/vnd.github.v3.raw'

    response = http_client.fetch(URL,headers=headers, method="GET", callback=handle_response)

    return response
