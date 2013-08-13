import os
from flask import Flask, render_template
from flask.ext.bootstrap import Bootstrap
from flask.ext.bouncer import Bouncer, UserAuthMixin, current_user, login_required, fresh_login_required
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over lazy dog'

# to send emails from a gmail account use the following config,
# replacing the last three settings with the correct values for
# the account
#app.config['MARROWMAILER_CONFIG'] = {
#    'manager.use': 'futures',
#    'transport.use': 'smtp',
#    'transport.host': 'smtp.gmail.com',
#    'transport.port': 465,
#    'transport.tls': 'ssl',
#    'transport.username': 'gmail-username',
#    'transport.password': 'gmail-password',
#    'message.author': 'Admin <admin@example.com>'
#}

# to get your own consumer key/secret pairs go to the following websites
# and create apps that represent your website.
# Facebook: https://developers.facebook.com/apps
# Twitter: https://dev.twitter.com/apps
# Google: https://code.google.com/apis/console

# note that the following consumer key/secret values will only work if you run
# your application on localhost
app.config['BOUNCER_CONFIG'] = {
    'oauth.facebook.consumer_key': '153128354894013',
    'oauth.facebook.consumer_secret': '63d0307b9e2ad3f989ebaa427e904822',
    'oauth.twitter.consumer_key': 'DKIj45IQ9WJpZtQFSRfpQ',
    'oauth.twitter.consumer_secret': 'WIesGjaWHjfFwLDu7uf0XnVItaa0WSw3TffDjEWK8lg',
    'oauth.google.consumer_key': '160777655273.apps.googleusercontent.com',
    'oauth.google.consumer_secret': 'BX5AzIWkUF9hKsopViLE3u53',
}
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

class User(UserAuthMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(64), unique = True, index = True)
    username = db.Column(db.String(64), unique = True, index = True)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean(), default = False)
    active = db.Column(db.Boolean(), default = True)
    social_id = db.Column(db.String(128), index = True)

    def __repr__(self):
        return '<User %r>' % (self.username)

    @classmethod
    def find(self, **kwargs):
        return self.query.filter_by(**kwargs).first()

    def save(self):
        db.session.add(self)
        if self.id is None:
            db.session.commit()

bouncer = Bouncer(app, User)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/loggedin')
@login_required
def loggedin():
    return render_template('loggedin.html')

@app.route('/fresh')
@fresh_login_required
def fresh():
    return render_template('fresh.html')
    
if __name__ == '__main__':
    if not os.path.exists('app.db'):
        db.create_all()
    app.run(debug = True)
