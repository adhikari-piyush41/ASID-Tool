import smtplib, ssl

port = 465
smtp_server = "smtp.gmail.com"
sender_email = "ha9562983@gmail.com"

password = input("Type your password and press enter: ")
receiver_email = input("Type the email to which you want to send mail: ")
SUBJECT = "Subject: Alert - Detected Security Incident"   
TEXT = "This message is send from the Correlation Script."
 
message = 'Subject: {}\n\n{}'.format(SUBJECT, TEXT)
# message = """"\
#     Subject: Alert From the Correlation Engine.

#     This message is send from the Correlation Script."""

# Create a secure ssl context
context = ssl.create_default_context()


with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, message)
    print ('Mail Sent')
