from flask import current_app
from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, BooleanField, HiddenField
from wtforms.validators import ValidationError, Required, Email, EqualTo

class BaseRegisterForm(Form):
    email = TextField('Email', validators = [ Required(), Email() ])
    username = TextField('Username', validators = [ Required() ])
    
    def validate_email(form, field):
        if current_app.bouncer.user_class.find(email = field.data):
            raise ValidationError('Email already registered')
            
    def validate_username(form, field):
        user_class = current_app.bouncer.user_class
        error = user_class.validate_username(field.data)
        if error:
            raise ValidationError(error)
        if user_class.find(username = field.data):
            raise ValidationError('Username already in use')

class RegisterForm(BaseRegisterForm):
    password = PasswordField('Password', validators = [ 
        Required(), EqualTo('password2', message = 'Passwords must match') ])
    password2 = PasswordField('Confirm password', validators = [ Required() ])

class LoginForm(Form):
    email = TextField('Email', validators = [ Email() ])
    password = PasswordField('Password', validators = [ Required() ])
    remember_me = BooleanField('Keep me logged in')

class ResetRequestForm(Form):
    email = TextField('Email', validators = [ Email() ])

class ResetForm(Form):
    token = HiddenField('Token')
    email = TextField('Email', validators = [ Email() ])
    password = PasswordField('Password', validators = [ 
        Required(), EqualTo('password2', message = 'Passwords must match') ])
    password2 = PasswordField('Confirm password', validators = [ Required() ])
    
class ChangeEmailForm(Form):
    email = TextField('New Email', validators = [ Email() ])
    password = PasswordField('Password', validators = [ Required() ])

class ChangePasswordForm(Form):
    old_password = PasswordField('Old password', validators = [ Required() ])
    password = PasswordField('New password', validators = [ 
        Required(), EqualTo('password2', message = 'Passwords must match') ])
    password2 = PasswordField('Confirm new password', validators = [ Required() ])

class RefreshForm(Form):
    email = TextField('Email', validators = [ Email() ])
    password = PasswordField('Password', validators = [ Required() ])

