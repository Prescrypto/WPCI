from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from tornado.template import Loader
from email import encoders
import config as conf
import smtplib


class Mailer(object):
    loader = Loader("templates/email")
    EMAIL_HTML_TEMPLATE = loader.load("document_send_email.html")
    def __init__(self, **kwargs):
        mandatory_args = ["username","password","server","port"]
        for x in mandatory_args:
            if kwargs.get(x, False) == False:
                raise ValueError("%s must be provided" % (x))
            self.__dict__[x] = kwargs[x]

    def send(self, **kwargs):

        mandatory_args = ["subject","email_from","emails_to","attachments_list"]
        for x in mandatory_args:
            if not kwargs.get(x, False):
                raise ValueError("%s is mandatory" % (x))

        toaddr_list = []
        for eaddress in kwargs['emails_to']:
            toaddr_list.append(eaddress)

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = kwargs['subject']
            msg['From'] = kwargs['email_from']
            msg['To'] = ','.join(kwargs['emails_to'])

            text = kwargs['text_message']
            html = kwargs['html_message']
            attachments_list = kwargs['attachments_list']
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

            #content = MIMEText(kwargs['content'], kwargs['content_type'])

            s = smtplib.SMTP(host=self.server, port=self.port)
            s.starttls()
            s.login(self.username, self.password)
            s.sendmail(msg['From'], msg['To'], msg.as_string())
            print(s.quit())
        except Exception as e:
            print("sending email", e)
