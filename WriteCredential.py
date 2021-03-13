file = '/Users/chloez/.aws/credentials'
with open(file, 'w') as filetowrite:
    myCredential = """[default]
aws_access_key_id=ASIAU3I5ZESRNLQVC44Y
aws_secret_access_key=g0r0rb9DmvtciGS4/GRuuiBKQcf86jUp8tUek5lh
aws_session_token=FwoGZXIvYXdzEL7//////////wEaDFiTFPz0fBbklGURuiLKATeQKRuHCyj5PfMixZay3G4Re59X11A+0nQm5fsEZaZ5pTtwVxiDzi4fQpUw6L16G3PgXd0qczU+5unnqmDheWjMNO+oZM1ERewqcaAX/GnVW1CxXoy5mp4aNQPZJqLcaP47Ojo/TJjWoaHPZE/UIQgKbxF7R6Ry3zJ5oGq2NtE4CTHUPYzQaHJ3/z4FsW1PMyG165Sw8YslcbX4GI8YNNi4jDf4nL8y5EZvjWD2/tH+AnLrLMmgjGXjOcZnpYnND4ZGANg5sIT+nEYo6+q9/gUyLTCJxqVfLbDm7j3U1ioO98ghM1+kltebJFkOhQnFnEDFUxMeXirndIcCJLI6pg=="""
    filetowrite.write(myCredential)

file='/Users/chloez/.aws/config'
with open(file, 'w') as filetowrite:
    myCredential = """[default] 
                       region = us-east-1
                       output = json
                       [profile prod]
                       region = us-east-1
                       output = json"""
    filetowrite.write(myCredential)