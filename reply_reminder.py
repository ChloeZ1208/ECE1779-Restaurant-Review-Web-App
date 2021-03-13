import boto3
from boto3 import dynamodb
from boto3.dynamodb.conditions import Key, Attr
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time


def send_reminder(emails):
	port = 587  
	password = "Ece1779pass"
	smtp_server = "smtp.live.com"
	# Send email here
	sender_email = "ece1779a3@hotmail.com"
	# Create the plain-text version of message
	msg = MIMEMultipart()
	msg['From'] = sender_email	
	msg['Subject'] = 'Response required'
	body = """\
	Just a friendly reminder that you have reviews needed to be replied, don't forget to reply them. Link: https://03rs8d4pzk.execute-api.us-east-1.amazonaws.com/production"""
	msg.attach(MIMEText(body, 'plain'))

	server = smtplib.SMTP(smtp_server, port)
	server.ehlo()
	server.starttls()
	server.ehlo()
	server.login(sender_email, password)
	for receiver_email in emails:
		msg['To'] = receiver_email
		server.sendmail(sender_email, receiver_email, msg.as_string())
		print ('done!')
		time.sleep(10)
	server.quit()


def check_review():
	dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

	# get all information from comment table
	table = dynamodb.Table('comment')
	response = table.scan()
	restaurants = set()
	for i in range(0, len(response['Items'])):
		# select comments that have not been replied
		if response['Items'][i]['reply'] == '':
			restaurants.add(response['Items'][i]['restaurant'])
	owner = []
	for restaurant in restaurants:
		table = dynamodb.Table('restaurant')
		response = table.scan(
			FilterExpression = Attr("name").eq(restaurant)
		)
		owner.append(response['Items'][0]['owner'])
	send_reminder(owner)

if __name__ == "__main__":
	check_review()