import logging
#mongodb
from pymongo import MongoClient
from pymongo.collation import Collation
from bson.objectid import ObjectId
#internal
import config as conf


# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

