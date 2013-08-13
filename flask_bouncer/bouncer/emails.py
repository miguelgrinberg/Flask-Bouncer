from flask import current_app
from flask.ext.marrowmailer import Mailer

_default_subjects = {
    'confirm': 'Confirm Your Account',
    'reset': 'Password Reset Confirmation',
    'change_email': 'Email Change Confirmation'
}

def send_email(template, user, email, **kwargs):
    if not hasattr(current_app, 'marrowmailer'):
        Mailer(current_app)
    mailer = current_app.marrowmailer
    
    subject = current_app.bouncer.get_config('email.subject.' + template, 
        _default_subjects.get(template) or template)
    signature = current_app.bouncer.get_config('email.signature', 'The Administrator')
    
    msg = mailer.new()
    if email is None:
        email = user.email
    msg.to = '%s <%s>' % (user.username, email)
    msg.subject = subject
    msg.render_template('bouncer/mail/' + template, user = user, signature = signature, **kwargs)
    mailer.send(msg)
    return msg
