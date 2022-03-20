import smtplib, ssl
from email.message import EmailMessage
from threading import *

class SendMail(Thread):

    def __init__(self, Content):
        super(SendMail, self).__init__()
        self.Content = Content
        
    def run(self):
        port = 465
        smtp_server = "smtp.gmail.com"
        sender_email = "ha9562983@gmail.com"
        password = "bh8xJce26MhJUF6"
        receiver_email = "adhikaripiyush41@gmail.com"
        # password = input("Type your password and press enter: ")
        # receiver_email = input("Type the email to which you want to send mail: ")
        Content = "This message is send from the Correlation Script."

        msg = EmailMessage()
        msg['Subject'] = 'Alert - Incident detected'
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg.set_content(self.Content)

        context = ssl.create_default_context()


        with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
            server.login(sender_email, password)
            server.send_message(msg)
            print ('Mail Sent')