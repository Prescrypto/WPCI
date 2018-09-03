from models.mongoManager import ManageDB
import pymongo
from pymongo import MongoClient
import config as conf
from passlib.context import CryptContext
import time
import logging
from models import User

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

NDA = "Nda"
pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=300
)


class Nda(object):

    def __init__(self, id=None):
        self.id = id

    def __str__(self):
        return "Nda(id='%s')" % self.id

    def __setitem__(self, name, value):
        self.__dict__[name] = value

    def set_attr(self, pdf, pdf_url, wp_url, wp_main_tex, org_name, org_address, org_type, nda_logo, userjson={}, email = None):
        try:
            self.pdf = pdf
            self.pdf_url = pdf_url
            self.wp_url = wp_url
            self.wp_main_tex = wp_main_tex
            self.org_name = org_name
            self.org_address = org_address
            self.org_type = org_type
            self.nda_logo = nda_logo
            self.email = email

            if userjson is not None and userjson != {}:
                #if the user is authenticated then use a different url with github authentication
                user = User.User(userjson.get("username"), userjson.get("password"))
                github_token = user.get_attribute('github_token')
                if github_token is None or github_token == '':
                    logger.info("github token error")
                    return False
                try:
                    self.pdf_url = "https://{}:x-oauth-basic@{}".format(github_token, self.pdf_url.split("://")[1])
                    self.wp_url = "https://{}:x-oauth-basic@{}".format(github_token, self.wp_url.split("://")[1])
                except:
                    logger.info("error getting correct url on git")
                    return False

            if self.id is None:
                self.id = '{}_nda_{}'.format(org_name.strip(), str(int(time.time() * 1000)))

            return True
        except Exception as e:
            logger.info(e)
            return False

    def check(self):
        '''finds a user'''
        result = False
        mydb = None
        try:
            collection = NDA
            mydb = ManageDB(collection)
            docs = mydb.select("id", self.id)
            if len(docs) > 0:
                result = True

        except Exception as e:
            logger.info("finding id"+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def find_by_id(self, id):
        '''finds a user'''
        result = None
        mydb = None
        if id is None or id == "":
            return None
        try:
            collection = NDA
            mydb = ManageDB(collection)
            docs = mydb.select("id", id)
            if len(docs) > 0:
                for key, value in docs[0].items():
                    self[key] = value
                return self

        except Exception as e:
            logger.info("finding id"+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def create(self):
        '''creates a new user on the bd'''
        result = False
        mydb = None

        if self.id is None:
            return result

        try:
            collection = NDA
            mydb = ManageDB(collection)
            temp_nda = self.__dict__
            result = mydb.insert_json(temp_nda)

        except Exception as error:
            logger.info("creating user"+ str(error))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def update(self):
        '''updates a user on the bd'''
        result = None
        mydb = None
        if self.id is None:
            return None
        try:
            collection = NDA
            mydb = ManageDB(collection)
            temp_nda= self.__dict__
            temp_nda.pop("id")
            result = mydb.update({"id": self.id}, temp_nda)

        except Exception as error:
            logger.info("updating user"+ str(error))
            result = None

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def get_attribute(self, attribute_name):
        '''gets the attribute from the bd'''
        result = False
        mydb = None
        try:
            collection = NDA
            mydb = ManageDB(collection)
            docs = mydb.select("id", self.id)
            if len(docs) > 0:
                result = docs[0].get(attribute_name)
        except:
            result = None

        finally:
            if mydb is not None:
                mydb.close()

        return result