import smtplib, ssl, yaml
from email.message import EmailMessage
from threading import *

# The class is used to send mail to the respective users set at config.yml file
class SendMail(Thread):

    #-------------------------------------------------------------------------------------------------------------------------
    def __init__(self, Content):
        super(SendMail, self).__init__()
        # Content receives the security incident detected log messages.
        self.Content = Content
    
    #-------------------------------------------------------------------------------------------------------------------------
    def run(self):

        # Opening the config.yml file for SMTP settings.
        with open('config.yml', 'r') as file:
            settings = yaml.safe_load(file)

        # Setting up open smtp to send mail to the specified users with subject and content.
        msg = EmailMessage()
        msg['Subject'] = 'Alert - Incident detected'
        msg['From'] = settings['Smtp']['senderMail']
        msg['To'] = settings['Smtp']['Mail']['receiverMail']
        msg['Cc'] = ', '.join(settings['Smtp']['Mail']['ccReceiverMail'])
        content = str(settings['Smtp']['content']) + "\n" + str(self.Content)
        msg.set_content(content)

        context = ssl.create_default_context()

        # Sends mail to the specified users set at config.yml file.
        try:
            with smtplib.SMTP_SSL(settings['Smtp']['smtp_server'], settings['Smtp']['port'], context=context) as server:
                server.login(settings['Smtp']['senderMail'], settings['Smtp']['senderPassword'])
                server.send_message(msg)
                print ('Mail Sent')
        except smtplib.SMTPAuthenticationError:
            print ("Mail Authentication Failure." + "\n" + "Please enter correct sender email address and password in the config.yml file!")
        
        #-------------------------------------------------------------------------------------------------------------------------