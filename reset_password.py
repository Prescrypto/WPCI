import logging
import click
#internal
import config as conf
from models import User


# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

@click.command()
@click.option('--username', default="", help='The user name you want to change the password')
@click.option('--password', default="", help='The new password of the user')

def reset_password(username, password):
    try:
        user = User.User(username, password)
        if user.find() is False:
            logger.info("there is no such a user")
        user.validate_email(password)
        logger.info("password successfully changed")
    except Exception as e:
        logger.info(str(e))

if __name__ == "__main__":
    reset_password()

