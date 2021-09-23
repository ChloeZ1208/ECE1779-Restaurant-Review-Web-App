# EC1779 - A Serverless Restaurant Review Web App
## Introduction
Integrated with Amazon Lambda to create a serverless flask application. Data is stored on S3 and DynamoDB. There types of account created. Owner could create restaurants and its basic information, as well as reply to the user's comments. While user was able to leave feedbacks and rate different restaurants. Admin account was able to delete comments and restaurants. In addition, an email notification feature is also running in the background which send emails to owners once new comments are posted towards their restaurants, using AWS CloudWatch, combined with SNS and Lambda in Python

## Tech Stack
Data Storage: AWS S3, AWS DynamoDB
Depolyment: AWS Lambda, Gateway
Framework: Flask, Bootstrap
Language: Python

