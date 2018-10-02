from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from tornado.template import Loader
import logging
from email import encoders
import config as conf
import smtplib

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')


class Mailer(object):
    def __init__(self, **kwargs):
        mandatory_args = ["username","password","host","port"]
        for x in mandatory_args:
            if kwargs.get(x, False) == False:
                raise ValueError("%s must be provided" % (x))
            self.__dict__[x] = kwargs[x]
        loader = Loader("templates/email")
        self.EMAIL_HTML_TEMPLATE = loader.load("document_send_email.html")


    def send(self, **kwargs):
        mandatory_args = ["subject","email_from","emails_to"]
        for x in mandatory_args:
            if not kwargs.get(x, False):
                raise ValueError("%s is mandatory" % (x))

        toaddr_list = []
        emails_bcc = kwargs.get('emails_bcc',[])
        for eaddress in kwargs['emails_to']:
            toaddr_list.append(eaddress)
        for eaddress in emails_bcc:
            toaddr_list.append(eaddress)
        try:
            msg = MIMEMultipart('mixed')
            msg['Subject'] = kwargs['subject']
            msg['From'] = kwargs['email_from']
            msg['To'] = ','.join(kwargs['emails_to'])
            msg['Bcc'] =  ','.join(emails_bcc)

            text = kwargs.get('text_message', '')
            html = kwargs.get('html_message', '')
            attachments_list = kwargs.get('attachments_list',[])
            if text is not None and text != "":
                msg.attach(MIMEText(text, 'plain'))
            if html is not None and html != "":
                html = self.EMAIL_HTML_TEMPLATE.generate(body_msg=html)
                msg.attach(MIMEText(html.decode("utf-8") , 'html'))

            for attachment in attachments_list:
                part = MIMEBase('application', attachment.get("file_type"))
                part.set_payload(open(attachment.get("file_path"), "rb").read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="' + attachment.get('filename') + '"')
                msg.attach(part)

            self.server = smtplib.SMTP(host=self.host, port=self.port)
            self.server.ehlo()
            self.server.starttls()
            self.server.ehlo()
            self.server.login(self.username, self.password)
            self.server.sendmail(msg['From'], toaddr_list, msg.as_string())
            logger.info(self.server.quit())
        except Exception as e:
            logger.info("error sending email"+ str(e))
