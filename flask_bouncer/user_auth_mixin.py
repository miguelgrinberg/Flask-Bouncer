import re
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app

class UserAuthMixin(object):
    @staticmethod
    def validate_username(username):
        if re.search('^[A-Za-z][A-Za-z0-9_]*$', username) != None:
            return None
        return "Usernames must begin with a letter and have only letters, numbers or underscores"
        
    @classmethod
    def get(self, id):
        return self.find(id = int(id))

    def get_id(self):
        return unicode(self.id)

    def is_authenticated(self):
        return True

    def is_active(self):
        return self.active

    def is_anonymous(self):
        return False

    def is_confirmed(self):
        return self.confirmed

    def is_social(self):
        return self.social_id != None and self.social_id != ''
        
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, pw):
        self.password_hash = self.hash_password(pw)

    def hash_password(self, pw):
        return pwd_context.encrypt(pw)

    def verify_password(self, pw):
        return pwd_context.verify(pw, self.password_hash)
        
    def _make_token(self, data, timeout):
        s = Serializer(current_app.config['SECRET_KEY'], timeout)
        return s.dumps(data)
        
    def _verify_token(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        return data
        
    def make_confirm_token(self, timeout = 3600):
        return self._make_token({ 'id': self.id, 'op': 'confirm' }, timeout)
        
    def verify_confirm_token(self, token):
        if self.is_confirmed():
            return False
        data = self._verify_token(token)
        if data and data.get('id') == self.id and data.get('op') == 'confirm':
            self.confirmed = True
            return True
        return False

    def make_reset_token(self, expiration = 3600):
        return self._make_token({ 'id': self.id, 'op': 'reset' }, expiration)
        
    def verify_reset_token(self, token):
        data = self._verify_token(token)
        if data and data.get('id') == self.id and data.get('op') == 'reset':
            return True
        return False

    def make_change_email_token(self, new_email, expiration = 3600):
        return self._make_token({ 'id': self.id, 'op': 'change', 'email': new_email }, expiration)

    def verify_change_email_token(self, token):
        data = self._verify_token(token)
        if data and data.get('id') == self.id and data.get('op') == 'change':
            email = data.get('email')
            if email:
                self.email = email
                self.confirmed = True
                return True
        return False
