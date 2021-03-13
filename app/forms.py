from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, DecimalField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message=u'Email can not be empty.'), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(message=u'Password can not be empty.'), Length(min=6, max=20), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class RegistrationForm_owner(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message=u'Email can not be empty.'), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(message=u'Password can not be empty.'), Length(min=6, max=20), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    restaurant_name = StringField('Restaurant Name',
                                  validators=[DataRequired(message=u'Please enter your Restaurant Name.')])
    restaurant_pic = FileField('File', validators=[FileRequired(),
                                         FileAllowed(['jpg', 'png', 'gif', 'jpeg'], 'Images only!')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email',
                           validators=[DataRequired(message=u'Email can not be empty.'), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(message=u'Password can not be empty.'), Length(min=6, max=20)])
    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message=u'Email can not be empty.'), Email()])
    submit = SubmitField('Send')

class ChangePasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message=u'Email can not be empty.'), Email()])
    old_password = PasswordField('Old password', validators=[DataRequired()])
    password = PasswordField('New password', validators=[DataRequired(), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm new password', validators=[DataRequired()])
    submit = SubmitField('Update Password')

def star_check(FlaskForm,field):
    if(field.data >5 or field.data < 0):
        raise ValidationError('Star must in the range of 0 to 5')

class writeReviewsForm(FlaskForm):
    comment = StringField('Comment',
                           validators=[DataRequired(message=u'Comment can not be empty.'), Length(min=1, max=100)])
    stars = DecimalField('Stars',
                             validators=[DataRequired(message=u'Stars can not be empty.'),star_check])
    submit = SubmitField('Submit')

class ReplyForm(FlaskForm):
    reply = StringField('Reply',
                           validators=[DataRequired(message=u'Comment can not be empty.'), Length(min=1, max=100)])
    submit = SubmitField('Submit')