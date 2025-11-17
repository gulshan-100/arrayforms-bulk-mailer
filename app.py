import urllib.parse
import werkzeug.urls
import re

# --- FIX FOR WERKZEUG / FLASK-WTF COMPATIBILITY ---
# Werkzeug >= 2.1 removed url_encode, Flask-WTF still tries to import it.
if not hasattr(werkzeug.urls, "url_encode"):
    werkzeug.urls.url_encode = urllib.parse.urlencode
# --------------------------------------------------

from flask import Flask, render_template, request, flash, redirect, url_for
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
import logging
import bleach
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, PasswordField, MultipleFileField
from wtforms.validators import DataRequired, Email, ValidationError
from werkzeug.utils import secure_filename

app = Flask(__name__)
# Use environment variable for secret key in production or generate a random one in development
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Configure upload settings
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'gif'}

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("arrayforms.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Email validation pattern
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class EmailForm(FlaskForm):
    """Form for sending bulk emails with validation"""
    
    def validate_emails(form, field):
        if not field.data.strip():
            raise ValidationError('Please enter at least one email address.')
        
        emails = [e.strip() for e in field.data.split(',') if e.strip()]
        
        if len(emails) > 10:
            raise ValidationError('Maximum 10 email recipients allowed.')
        
        invalid_emails = [email for email in emails if not EMAIL_REGEX.match(email)]
        if invalid_emails:
            raise ValidationError(f'Invalid email format: {", ".join(invalid_emails)}')
    
    sender_email = StringField('Your Email', validators=[
        DataRequired(message='Please enter your email address.'),
        Email(message='Please enter a valid email address.')
    ])
    
    sender_password = PasswordField('Email Password/App Password', validators=[
        DataRequired(message='Please enter your password or app password.')
    ])
    
    emails = TextAreaField('Recipient Emails', validators=[
        DataRequired(message='Please enter recipient email addresses.'),
        validate_emails
    ])
    
    subject = StringField('Subject', validators=[
        DataRequired(message='Please enter an email subject.')
    ])
    
    body = TextAreaField('Message', validators=[
        DataRequired(message='Please enter an email body.')
    ])
    
    attachments = MultipleFileField('Attachments', validators=[
        FileAllowed(ALLOWED_EXTENSIONS, 'Only PDF, DOC, DOCX, TXT, JPG, JPEG, PNG, and GIF files are allowed!')
    ])

@app.route('/', methods=['GET', 'POST'])
def index():
    form = EmailForm()
    if request.method == 'POST' and form.validate_on_submit():
        return send_emails(form)
    return render_template('index.html', form=form)

@app.route('/gmail-help')
def gmail_help():
    return render_template('gmail_help.html')

def process_links_for_email(html_content):
    """
    Process HTML content to make links more email-client friendly
    """
    # Pattern to find URLs in href attributes and plain text
    url_pattern = r'(https?://[^\s<>"\']+)'
    
    def replace_url(match):
        url = match.group(1)
        # Create a proper HTML link with styling to prevent breaking
        return f'<a href="{url}" style="word-break: break-all; white-space: nowrap; display: inline-block;">{url}</a>'
    
    # First, handle URLs that are not already in href attributes
    # Look for URLs that are not preceded by href="
    text_url_pattern = r'(?<!href=")(?<!href=\')(' + url_pattern[1:-1] + r')(?![^<]*</a>)'
    html_content = re.sub(text_url_pattern, replace_url, html_content)
    
    # Add CSS styles to existing links to prevent word breaking
    html_content = re.sub(
        r'<a\s+([^>]*href=[^>]*)>',
        r'<a \1 style="word-break: keep-all; white-space: nowrap; text-decoration: none;">',
        html_content
    )
    
    return html_content

def create_email_safe_html(body):
    """
    Create email-safe HTML content with proper link handling
    """
    # First clean the HTML with bleach and remove any word-break tags
    safe_html_body = bleach.clean(
        body,
        tags=['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'a', 'img', 'span', 'div', 'b', 'i', 'font'],
        attributes={
            'a': ['href', 'target', 'style'], 
            'img': ['src', 'alt', 'width', 'height'], 
            'span': ['style'], 
            'div': ['style'], 
            'font': ['face', 'size', 'color'],
            'p': ['style'],
            'h1': ['style'],
            'h2': ['style'],
            'h3': ['style'],
            'h4': ['style'],
            'h5': ['style'],
            'h6': ['style']
        }
    )
    
    # Remove any word-break tags that might have been added by the rich text editor
    safe_html_body = re.sub(r'<wbr\s*/?>', '', safe_html_body)
    safe_html_body = re.sub(r'<\s*wbr\s*>', '', safe_html_body)
    
    # Process links to make them email-client friendly
    safe_html_body = process_links_for_email(safe_html_body)
    
    # Ensure proper HTML structure for email clients
    if not safe_html_body.strip().startswith('<'):
        safe_html_body = f'<p>{safe_html_body}</p>'
    
    # Wrap in a proper email HTML structure
    email_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
            a {{ color: #0066cc; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            p {{ margin: 10px 0; }}
            .email-content {{ max-width: 600px; }}
        </style>
    </head>
    <body>
        <div class="email-content">
            {safe_html_body}
        </div>
    </body>
    </html>
    """
    
    return email_html

def send_emails(form):
    """Process the email form and send emails to recipients"""
    
    sender_email = form.sender_email.data
    sender_password = form.sender_password.data
    raw_emails = form.emails.data
    subject = form.subject.data
    body = form.body.data
    
    recipients = [e.strip() for e in raw_emails.split(',') if e.strip()]
    smtp_settings = get_smtp_settings(sender_email)
    
    # Handle file attachments
    attachment_files = []
    if form.attachments.data:
        for file in form.attachments.data:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                attachment_files.append({
                    'path': file_path,
                    'filename': filename
                })
                logger.info(f"Attachment saved: {filename}")
    
    # Create email-safe HTML content
    safe_html_body = create_email_safe_html(body)
    
    success_count = 0
    failed_emails = []

    logger.info(f"Starting to send emails to {len(recipients)} recipients from {sender_email}")

    try:
        retry_count = 0
        max_retries = 3
        connected = False
        
        while not connected and retry_count < max_retries:
            try:
                server = smtplib.SMTP(smtp_settings['server'], smtp_settings['port'], timeout=10)
                server.starttls()
                connected = True
            except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as e:
                retry_count += 1
                logger.warning(f"SMTP connection attempt {retry_count} failed: {str(e)}")
                if retry_count >= max_retries:
                    raise
        
        try:
            server.login(sender_email, sender_password)
            
            for recipient in recipients:
                try:
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = subject
                    msg['From'] = sender_email
                    msg['To'] = recipient
                    
                    # Create plain text version by stripping HTML tags and handling entities
                    plain_text_body = re.sub(r'<[^>]+>', '', body)
                    # Replace common HTML entities
                    plain_text_body = plain_text_body.replace('&nbsp;', ' ')
                    plain_text_body = plain_text_body.replace('&amp;', '&')
                    plain_text_body = plain_text_body.replace('&lt;', '<')
                    plain_text_body = plain_text_body.replace('&gt;', '>')
                    plain_text_body = plain_text_body.replace('&quot;', '"')
                    plain_text_body = plain_text_body.replace('&#39;', "'")
                    # Clean up whitespace
                    plain_text_body = re.sub(r'\s+', ' ', plain_text_body).strip()
                    
                    text_part = MIMEText(plain_text_body, 'plain')
                    html_part = MIMEText(safe_html_body, 'html')
                    msg.attach(text_part)
                    msg.attach(html_part)
                    
                    # Attach files
                    for attachment in attachment_files:
                        try:
                            with open(attachment['path'], 'rb') as f:
                                part = MIMEBase('application', 'octet-stream')
                                part.set_payload(f.read())
                            
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= {attachment["filename"]}'
                            )
                            msg.attach(part)
                            logger.info(f"Attachment {attachment['filename']} added to email for {recipient}")
                        except Exception as e:
                            logger.error(f"Failed to attach {attachment['filename']}: {str(e)}")
                    
                    server.sendmail(sender_email, [recipient], msg.as_string())
                    success_count += 1
                    logger.info(f"Email sent to {recipient}")
                except Exception as e:
                    failed_emails.append(recipient)
                    logger.error(f"Failed to send email to {recipient}: {str(e)}")
            
            server.quit()
            
            # Clean up uploaded files
            for attachment in attachment_files:
                try:
                    os.remove(attachment['path'])
                    logger.info(f"Cleaned up attachment: {attachment['filename']}")
                except Exception as e:
                    logger.error(f"Failed to clean up {attachment['filename']}: {str(e)}")
            
            if success_count == len(recipients):
                logger.info(f"All {success_count} emails sent successfully")
                return render_template('success.html', recipient_count=success_count)
            elif success_count > 0:
                logger.warning(f"Partially successful: {success_count} of {len(recipients)} emails sent")
                flash(f'Partially successful: {success_count} of {len(recipients)} emails sent. Failed recipients: {", ".join(failed_emails)}', 'warning')
                return redirect(url_for('index'))
            else:
                logger.error(f"Failed to send any emails")
                flash('Failed to send any emails.', 'danger')
                return redirect(url_for('index'))
                
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"Authentication error: {str(e)}")
            if 'gmail' in sender_email.lower() and ('Username and Password not accepted' in str(e) or 'BadCredentials' in str(e)):
                flash('Gmail authentication failed. You must use an App Password, not your regular Gmail password. '
                      'Go to Google Account > Security > App passwords to create one. '
                      'See instructions on the form below.', 'danger')
            else:
                flash(f'Authentication error: {str(e)}. Please check your email and password.', 'danger')
            return redirect(url_for('index'))
        finally:
            if 'server' in locals():
                try:
                    server.quit()
                except:
                    pass
    except Exception as e:
        logger.error(f"Error in send_emails: {str(e)}", exc_info=True)
        flash(f'Error connecting to email server: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/send', methods=['POST'])
def send():
    return redirect(url_for('index'))

def get_smtp_settings(email):
    domain = email.split('@')[-1].lower()
    
    if 'gmail' in domain:
        return {'server': 'smtp.gmail.com', 'port': 587}
    elif 'yahoo' in domain:
        return {'server': 'smtp.mail.yahoo.com', 'port': 587}
    elif 'outlook' in domain or 'hotmail' in domain or 'live' in domain:
        return {'server': 'smtp.office365.com', 'port': 587}
    else:
        return {'server': f'smtp.{domain}', 'port': 587}

if __name__ == '__main__':
    # Get port from environment variable (for Render) or use default
    port = int(os.environ.get('PORT', 5000))
    # Use 0.0.0.0 to bind to all available network interfaces
    app.run(host='0.0.0.0', port=port, debug=False)
