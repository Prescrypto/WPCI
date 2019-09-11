#python
import tempfile
import io
import fitz

#web
import jinja2
from tornado import gen
from tornado.ioloop import IOLoop

# internal
from models import Document, Link, signerUser
from handlers.emailHandler import Mailer
from utils import *


#google oauth
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.http import MediaIoBaseDownload


latex_jinja_env = jinja2.Environment(
    block_start_string='\BLOCK{',
    block_end_string='}',
    variable_start_string='${{',
    variable_end_string='}}$',
    comment_start_string='\#{',
    comment_end_string='}',
    line_statement_prefix='%%line',
    line_comment_prefix='%#line',
    trim_blocks=True,
    autoescape=False,
    loader=jinja2.FileSystemLoader(os.path.abspath('/'))
)

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

#HTML EMAIL TEMPLATES
DEFAULT_HTML_TEXT = \
            "<h3>Hello,</h3>\
            <p>You will find the documentation you requested attached, thank you very much for your interest.</p>\
            <p>Best regards,</p>"
NOTIFICATION_HTML = \
            "<h3>Hi!</h3>\
            <p> {} has just downloaded the following document {}!</p>\
            <p>You can view detailed analytics here: <a href='{}'>{}</a></p>\
            <p>Keep crushing it!</p>\
            <p>WPCI Admin</p>"


class manageDocuments():

    document = None
    user = None
    signer_user = None
    google_credentials = None
    git_credentials = None

    def __init__(self, doc_id=None):
        if doc_id:
            try:
                doc = Document.Document()
                self.document = doc.find_by_doc_id(doc_id)
                user = User.User()
                self.user = user.find_by_attr("org_id", self.document.org_id)
            except Exception as e:
                logger.info(F"[error renderPDF init] obtaining document from docid: {str(e)}")

    def is_valid_document(self):

        if self.document and self.user:
            return True

        else:
            return False

    def get_document_by_link_id(self, link_id):
        try:
            doc_id = "_".join(link_id.split("_")[:-1])
        except Exception as e:
            logger.info(F"[error get_document_by_link_id] obtaining link id: {str(e)}")
            return False
        try:
            doc = Document.Document()
            self.document = doc.find_by_doc_id(doc_id)
            user = User.User()
            self.user = user.find_by_attr("org_id", self.document.org_id)
        except Exception as e:
            logger.info(F"[error get_document_by_link_id] obtaining document from linkid: {str(e)}")
            return False

        return True

    def get_document_by_doc_id(self, doc_id):
        try:
            doc = Document.Document()
            self.document = doc.find_by_doc_id(doc_id)
            user = User.User()
            self.user = user.find_by_attr("org_id", self.document.org_id)
        except Exception as e:
            logger.info(F"[error get_document_by_doc_id] obtaining document from docid: {str(e)}")
            return False

        return True

    def set_google_credentials(self):

        if self.user:
            google_token = getattr(self.user, "google_token", False)
            if google_token is not False:
                self.google_credentials = {
                    'token': self.user.google_token,
                    'refresh_token': self.user.google_refresh_token,
                    'token_uri': conf.GOOGLE_TOKEN_URI,
                    'client_id': conf.GOOGLE_CLIENT_ID,
                    'client_secret': conf.GOOGLE_CLIENT_SECRET,
                    'scopes': conf.SCOPES
                }
                return True
        return False

    def download_and_sign_google_doc(self, pdf_id, timestamp_now):
        MORPH = None
        watermark = "Document generated for: " + self.signer_user.email
        complete_hash = get_hash([timestamp_now, self.signer_user.email], [pdf_id])
        # Load credentials from the session.
        credentials = google.oauth2.credentials.Credentials(
            **self.google_credentials
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                file_full_path64 = tmpdir + "/" + pdf_id + ".base64"
                file_full_path = tmpdir + "/" + pdf_id + ".pdf"
                drive = googleapiclient.discovery.build(
                    conf.API_SERVICE_NAME, conf.API_VERSION, credentials=credentials)

                request = drive.files().export_media(fileId=pdf_id,
                                                     mimeType='application/pdf')
                metadata = drive.files().get(fileId=pdf_id).execute()
                file_tittle = metadata.get("title").strip(" ") + ".pdf"
                modified_date = metadata.get("modifiedDate")
                mime_type = metadata.get("mimeType")

                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request, chunksize=conf.CHUNKSIZE)
                done = False
                while done is False:
                    status, done = downloader.next_chunk()

                with open(file_full_path, 'wb') as mypdf:
                    mypdf.write(fh.getvalue())

                if mime_type == "application/vnd.google-apps.presentation":
                    pointa = fitz.Point(conf.AXIS_X, conf.AXIS_Y - conf.PRESENTATION_OFFSET)
                    pointb = fitz.Point(conf.AXIS_X_LOWER, conf.AXIS_Y - conf.PRESENTATION_OFFSET)
                elif mime_type == "application/vnd.google-apps.spreadsheet":
                    pointa = fitz.Point(conf.AXIS_X, conf.AXIS_Y)
                    pointb = fitz.Point(conf.AXIS_X_LOWER, conf.AXIS_Y)

                else:
                    pointa = fitz.Point(conf.AXIS_X, conf.AXIS_Y_GOOGLE)
                    pointb = fitz.Point(conf.AXIS_X_LOWER,conf. AXIS_Y_GOOGLE)
                    MORPH = (pointb, conf.FLIP_MATRIX)

                document = fitz.open(file_full_path)
                for page in document:
                    page.insertText(pointa, text=watermark, fontsize=conf.WATERMARK_SIZE, fontname=conf.WATERMARK_FONT,
                                    rotate=conf.WATERMARK_ROTATION, morph=MORPH)
                    page.insertText(pointb, text="DocId: " + complete_hash, fontsize=conf.WATERMARK_SIZE,
                                    fontname=conf.WATERMARK_FONT, rotate=conf.WATERMARK_ROTATION, morph=MORPH)
                document.save(file_full_path, incremental=1)
                document.close()

                pdffile = open(file_full_path, 'rb').read()

                return pdffile, complete_hash, file_tittle

            except IOError as e:
                logger.info('google render IOError' + str(e))
                return None, None, None
            except Exception as e:
                logger.info("other error google render" + str(e))
                return None, None, None

    def render_document(self, timestamp_now, email, name):
        pdffile = None
        doc_type = getattr(self.document, "render", "")
        self.signer_user = signerUser.SignerUser(email, name)
        # create the signer user so it can generate their keys
        self.signer_user.create()

        if doc_type == conf.GOOGLE:
            self.set_google_credentials()
            doc_google_id = get_id_from_url(self.document.doc_url)
            pdffile, complete_hash, file_tittle = self.download_and_sign_google_doc(
                doc_google_id,
                timestamp_now
            )
            return pdffile, complete_hash, file_tittle

        elif doc_type == conf.LATEX:
            return None, None, None

        elif doc_type == conf.EXTERNAL:
            return None, None, None

    @gen.engine
    def render_and_send_all_documents(self, email, name, email_body_html, main_tex="main.tex", email_body_text=""):
        """ Trigger the renderization of the documents/contracts related to this doc object """
        ATTACH_CONTENT_TYPE = 'octet-stream'
        render_doc = False
        attachment_list = []
        render_contract = False
        timestamp_now = str(int(time.time()))
        error = ""

        with tempfile.TemporaryDirectory() as tmp_dir:

            try:
                # Check which of the documents are going to be rendered
                if self.document.type == conf.DOCUMENT:
                    render_doc = True

                elif self.document.type == conf.CONTRACT:
                    render_contract = True

                else:
                    render_doc = True
                    render_contract = True

                if render_doc:
                    try:
                        doc_file_path = os.path.join(tmp_dir, conf.DOC_FILE_NAME)
                        s3_file_name = F"doc_{self.signer_user.email}_{self.link_id}_{timestamp_now}.pdf"
                        pdf_file, complete_hash, file_tittle = self.render_document(
                            timestamp_now,
                            email,
                            name
                        )
                        with open(doc_file_path, 'wb') as temp_file:
                            temp_file.write(pdf_file)

                        uploaded_document_url = upload_to_s3(doc_file_path, s3_file_name)
                        self.signer_user.s3_doc_url = S3_BASE_URL.format(s3_file_name)
                        self.signer_user.update()
                        # this is the payload for the white paper file
                        doc_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                              file_path=doc_file_path,
                                              filename=conf.DOC_FILE_NAME)
                        attachment_list.append(doc_attachment)
                    except Exception as e:
                        logger.error(F"[ERROR render_and_send_all_documents] {e}")
                        error = "couldn't render the document"

                if render_contract:
                    pass

                if error != "":
                    logger.info("There was an error on the documents rendering: {}".format(error))
                else:
                    self.send_attachments(attachment_list, email_body_html, email_body_text)

            except Exception as e:
                logger.info("error rendering documents: {}".format(str(e)))
                error = "error rendering document"
            finally:
                return attachment_list, error

    def send_attachments(self, attachment_list, email_body_html, email_body_text):
        """Send a list of attachments to the signer and organization"""
        BASE_PATH = "/docs/"
        mymail = Mailer(username=conf.SMTP_USER, password=conf.SMTP_PASS, host=conf.SMTP_ADDRESS, port=conf.SMTP_PORT)

        if not email_body_html:
            email_body_html = DEFAULT_HTML_TEXT

        # send the email with the result attachments
        sender_format = "{} <{}>"
        loader = Loader("templates/email")
        button = loader.load("cta_button.html")
        notification_subject = F"Your Document {self.document.doc_id} has been downloaded"
        analytics_link = F"{conf.BASE_URL}{BASE_PATH}analytics/{self.document.doc_id}"

        mymail.send(subject=self.document.doc_name,
                    email_from=sender_format.format(self.user.org_name, conf.SMTP_EMAIL),
                    emails_to=[self.signer_user.email],
                    attachments_list=attachment_list,
                    html_message=email_body_html + button.generate().decode("utf-8"),
                    text_message=email_body_text)

        html_text = NOTIFICATION_HTML.format(self.signer_user.email, self.document.doc_id, analytics_link,
                                             analytics_link)
        mymail.send(subject=notification_subject,
                    attachments_list=attachment_list,
                    email_from=sender_format.format("WPCI Admin", conf.SMTP_EMAIL),
                    emails_to=[self.user.org_email], html_message=html_text,
                    text_message=email_body_text)

    def render_contract(self):
        return None

    def get_b64_pdf_from_document(self):
        '''Call the render function and retrive a base 64 pdf'''
        result = False
        try:

            return None

        except Exception as e:
            logger.info("error rendering the document link " + str(e))

        return result