#python
import time
import hashlib
import re
import logging
import os
import binascii
import base64
import random 
import _pickle as cPickle
from collections import OrderedDict


#Cryptographic library
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

#external app
from jira import JIRA
import tinys3

#web app
from tornado.template import Loader

#internal
import config as conf
from models import User
from models.mongoManager import ManageDB

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')


ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
# S3 PATHS
FOLDER = "signed_files/"
BUCKET = "wpci-signed-docs"
S3_BASE_URL = "https://s3-us-west-2.amazonaws.com/"+BUCKET+"/"+FOLDER+"{}"


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
        logger.error("Error al Crear Issue en JIRA : %s." % e)


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


def generate_credentials():
    loader = Loader("static/auth")
    my_cred_file = loader.load("google_secret_format.txt")
    result = my_cred_file.generate().decode("utf-8") % (conf.GOOGLE_CLIENT_ID, conf.GOOGLE_PROJECT_ID, conf.GOOGLE_CLIENT_SECRET, conf.BASE_URL+"/docs/")
    with open(conf.CLIENT_SECRETS_FILE, "w") as cred_json:
        cred_json.write(result)


def ordered_data(data):
    ''' Orderer data '''
    if data is None:
        return data

    if isinstance(data, list):
        _new_list = []
        for item in data:
            _new_list.append(dict(OrderedDict(sorted(item.items(), key=lambda x: x[0]))))

        return _new_list

    else:
        _new_dict = {}
        try:
            _new_dict = OrderedDict(sorted(data.items(), key=lambda x: x[0]))
        except Exception as e:
            logger.info("ordering data {}".format(e))
            return data

        return dict(_new_dict)


def iterate_and_order_json(json_data):
    '''iterates over a json to order all the sub jsons and lists'''

    temp_dict = dict()

    if not json_data or not isinstance(json_data, dict):
        return json_data
    try:
        for key, val in json_data.items():
            temp_dict[key] = ordered_data(val)
    except Exception as e:
        logger.error("[iterate_and_order_json ERROR]: {}, type:{}".format(e, type(e)))
        return json_data

    return temp_dict


def upload_to_s3(file_path, file_name):
    """Upload a file to the default S3 bucket"""
    try:
        s3_connection = tinys3.Connection(conf.ACCESS_KEY, conf.SECRET_KEY, tls=True, default_bucket=BUCKET)
        with open(file_path, 'rb') as temp_file:
            s3_connection.upload(FOLDER+file_name, temp_file, public=False)
        return S3_BASE_URL.format(file_name)
    except Exception as e:
        logger.info("Error uploading files: {}".format(str(e)))
        return ""


def sign_document_hash(signer_user, document_bytes):
    """Use the signer document hash to create a signature for it"""
    try:
        crypto_tool = CryptoTools()
        document_hash = get_hash(document_bytes, hashes_list=[])

        signer_user.sign = crypto_tool.sign(
            document_hash.encode('utf-8'),
            crypto_tool.import_RSA_string(signer_user.priv_key)
        ).decode('utf-8')

        signer_user.update()

        return signer_user
    except Exception as e:
        logger.info("ERROR creating document hash signature: {}".format(str(e)))
        return False


class CryptoTools(object):
    """Object tools for encrypt and decrypt info"""
    
    def __init__(self, has_legacy_keys=False, *args, **kwargs):
        #This number is the entropy created by the user in FE, your default value is 161  
        self.ENTROPY_NUMBER = self._number_random()
        self.logger = logging.getLogger('django_info')
        self.has_legacy_keys = has_legacy_keys

    def _number_random(self):
        '''Take a number between 180 to 220'''
        return random.randint(180,220)

    def bin2hex(self, binStr):
        '''convert str to hex '''
        return binascii.hexlify(binStr)

    def hex2bin(self, hexStr):
        '''convert hex to str '''
        return binascii.unhexlify(hexStr)

    def get_new_asym_keys(self, keysize=2048):
        ''' Return tuple of public and private key '''
        # LEGACY METHOD 
        privatekey = RSA.generate(2048)
        publickey = privatekey.publickey()
        return (publickey, privatekey)
    
    def _get_new_asym_keys(self, keysize=512):
        ''' Return tuple of public and private key '''
        #LEGACY METHOD
        return rsa.newkeys(keysize)

    def get_pem_format(self, EncryptionKey):
        ''' return the key on pem string format '''
        if self.has_legacy_keys:
            return EncryptionKey.save_pkcs1(format="PEM")
        else:
            return EncryptionKey.exportKey('PEM')

    def savify_key(self, EncryptionKeyObject):
        ''' Give it a key, returns a hex string ready to save '''
        if self.has_legacy_keys:
            return self._savify_key(EncryptionKeyObject)
        else:
            pickld_key = EncryptionKeyObject.exportKey('PEM')
            return self.bin2hex(pickld_key)
     
    def _savify_key(self, EncryptionKeyObject):
        ''' Give it a key, returns a hex string ready to save '''
        # LEGAY METHOD
        pickld_key = cPickle.dumps(EncryptionKeyObject)
        return self.bin2hex(pickld_key)

    def un_savify_key(self, HexPickldKey):
        ''' Give it a hex saved string, returns a Key object ready to use'''
        if self.has_legacy_keys:
            return self._un_savify_key(HexPickldKey)
        else:
            bin_str_key = self.hex2bin(HexPickldKey)
            #return objetc of RSA type  
            return RSA.importKey(bin_str_key)
     
    def _un_savify_key(self, HexPickldKey):
        ''' Give it a hex saved string, returns a Key object ready to use  '''
        # LEGACY METHOD
        bin_str_key = self.hex2bin(HexPickldKey)
        return cPickle.loads(bin_str_key)

    def encrypt_with_public_key(self, message, EncryptionPublicKey):
        ''' Encrypt with PublicKey object '''
        if self.has_legacy_keys:
            return self._encrypt_with_public_key(message, EncryptionPublicKey)
        else:
            encrypt_rsa = PKCS1_OAEP.new(EncryptionPublicKey)
            encryptedtext = encrypt_rsa.encrypt(message)              
            return encryptedtext

    def _encrypt_with_public_key(self, message, EncryptionPublicKey):
        ''' Encrypt with PublicKey object '''
        # LEGACY METHOD
        encryptedtext=rsa.encrypt(message, EncryptionPublicKey)
        return encryptedtext

    def decrypt_with_private_key(self, encryptedtext, EncryptionPrivateKey):
        ''' Decrypt with PrivateKey object '''
        if self.has_legacy_keys:
            return self._decrypt_with_private_key(encryptedtext, EncryptionPrivateKey) 
        else:
            decrypt_rsa = PKCS1_OAEP.new(EncryptionPrivateKey)
            message = decrypt_rsa.decrypt(encryptedtext)
            return message

    def _decrypt_with_private_key(self, encryptedtext, EncryptionPrivateKey):
        ''' Decrypt with PrivateKey object '''
        # LEGACY METHOD
        message =rsa.decrypt(encryptedtext, EncryptionPrivateKey)
        return message

    def sign(self, message, PrivateKey):
        ''' Sign a message '''
        if self.has_legacy_keys:
            return self._sign(message, PrivateKey)
        else:
            message_hash = SHA256.new(message)
            signature = pkcs1_15.new(PrivateKey).sign(message_hash)

        return base64.b64encode(signature)

    def _sign(self, message, PrivateKey):
        ''' Sign a message '''
        # LEGACY METHOD
        signature = rsa.sign(message, PrivateKey, 'SHA-1')
        return base64.b64encode(signature)

    def verify(self, message, signature, PublicKey):
        '''Verify if a signed message is valid'''
        if self.has_legacy_keys:
            return self._verify(message, signature, PublicKey)
        else:
            signature = base64.b64decode(signature)
            message_hash = SHA256.new(message)
            try:
                pkcs1_15.new(PublicKey).verify(message_hash, signature)
                return True   
            except Exception as e:
                self.logger.error("[CryptoTool, verify ERROR ] Signature or message are corrupted")
                return False

    def _verify(self, message, signature, PublicKey):
        '''Verify if a signed message is valid '''
        # LEGACY METHOD
        signature = base64.b64decode(signature)
        try:
            return rsa.verify(message, signature, PublicKey)
        except Exception as e:
            self.logger.error("[CryptoTool, verify ERROR ] Signature or message are corrupted")
            return False

    def entropy(self, number):
        '''This method verify if entropy is enough'''
        if self.ENTROPY_NUMBER > 160:
            return os.urandom(self.ENTROPY_NUMBER)
        else:
            raise ValueError('Error')

    def create_key_with_entropy(self):
        '''This method create a pair RSA keys with entropy created by the user in FE'''
        try:
            privatekey = RSA.generate(2048, randfunc=self.entropy)
        except Exception as e:
            self.logger.error('{}'.format(e))
            self.logger.error("[CryptoTool, create_key_with_entropy ERROR] Entropy not enough")
            privatekey = None
        
        if privatekey is None:
            logger.info("Keys are null")
            publickey = None
        else: 
            publickey = privatekey.publickey()

        return (publickey, privatekey)

    def fiel_to_rsakeys(directory_file, password):
        '''This method generates your private key and public key in pem format 
        from your FIEL file in key format
        directorty_file: Only copy the direction file without extension, i.e., 
        wihtout .key
        password: enter password of your FIEL 
        '''
        privatekey = None
        with open(directory_file+'.key', 'rb') as file:
            privatekey = RSA.import_key(file.read(), passphrase=password)
        
        public_key = privatekey.publickey()
        return public_key, privatekey

    def import_RSA_string(self, rsa_key):
        '''This method create and return a object RSA from RSA private key in
        format PEM of type string if RSA private key is correct in other case return
        null '''
        try:
            return RSA.import_key(rsa_key)
        except Exception as e:
            self.logger.error('{}'.format(e))
            return None
