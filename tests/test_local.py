import re
import unittest
from flask import Flask
from flask.ext.bouncer import Bouncer, UserAuthMixin, current_user, login_required, fresh_login_required
from bs4 import BeautifulSoup

app = Flask(__name__)
app.config['SECRET_KEY'] = 'flask-bouncer secret key'
app.config['MARROWMAILER'] = { 'manager.use': 'futures', 'transport.use': 'mock' }

class User(UserAuthMixin):
    id_counter = 0
    users = []
    
    def __init__(self, **kwargs):
        self.id_counter = self.id_counter + 1
        self.id = self.id_counter
        self.email = kwargs.get('email')
        self.username = kwargs.get('username')
        self.password_hash = None
        if kwargs.get('password'):
            self.password = kwargs.get('password')
        self.confirmed = kwargs.get('confirmed', False)
        self.active = kwargs.get('active', True)
        self.social_id = None
        self.users.append(self)
        
    @classmethod
    def find(self, **kwargs):
        for user in self.users:
            found = True
            for kw in kwargs:
                if kwargs.get(kw) != getattr(user, kw):
                    found = False
                    break
            if found:
                return user
        return None

    def save(self):
        pass

bouncer = Bouncer(app, User)

@app.route('/')
def index():
    return 'all'

@app.route('/loggedin')
@login_required
def loggedin():
    return 'loggedin'

@app.route('/fresh')
@fresh_login_required
def fresh():
    return 'fresh'

class LocalLoginTestCase(unittest.TestCase):
    def setUp(self):
        User.users = []
        self.app = app.test_client()
        pass

    def tearDown(self):
        pass

    def _post_form(self, url, data, follow_redirects = False):
        r = self.app.get(url)
        assert r.status_code == 200
        soup = BeautifulSoup(r.data)
        csrf_token = soup.find(id = 'csrf_token')['value']
        data['csrf_token'] = csrf_token
        r = self.app.post(url, data = data, follow_redirects = follow_redirects)
        return r
        
    def _register(self, email, username, password):
        r = self._post_form('/auth/register', {
            'email': email,
            'username': username,
            'password': password,
            'password2': password,
        })
        assert r.status_code == 302

    def _login(self, email, password, rememberMe = False):
        r = self._post_form('/auth/login', {
            'email': email,
            'password': password,
            'remember_me': rememberMe
        }, False)
        assert r.status_code == 302
        return r

    def test_notLogged(self):
        r = self.app.get('/')
        assert r.status_code == 200
        assert r.data == 'all'

    def test_redirect(self):
        r = self.app.get('/loggedin')
        assert r.status_code == 302
        r = self.app.get(r.headers.get('Location'))
        assert r.status_code == 200
        soup = BeautifulSoup(r.data)
        csrf_token = soup.find(id = 'csrf_token')['value']
        assert csrf_token is not None and len(csrf_token) > 0

    def test_registerWithPasswordMismatch(self):
        r = self._post_form('/auth/register', {
            'email': 'me@me.com',
            'username': 'me',
            'password': 'p',
            'password2': 'p2'
        })
        soup = BeautifulSoup(r.data)
        assert soup.find(class_ = 'help-inline').string == 'Passwords must match'

    def test_register(self):
        r = self._post_form('/auth/register', {
            'email': 'me@me.com',
            'username': 'me',
            'password': 'p',
            'password2': 'p'
        })
        assert r.status_code == 302
        
    def test_login(self):
        self._register('me@me.com', 'me', 'p')
        r = self._post_form('/auth/login?next=%2Ffresh', {
            'email': 'me@me.com',
            'password': 'p'
        }, True)
        assert r.status_code == 200
        assert r.data == 'fresh'
    
    def test_loginWithBadPassword(self):
        self._register('me@me.com', 'me', 'p')
        r = self._post_form('/auth/login?next=%2Ffresh', {
            'email': 'me@me.com',
            'password': 'q'
        }, True)
        assert r.status_code == 200
        assert r.data != 'fresh'

    def test_confirm(self):
        self._register('me@me.com', 'me', 'p')
        self._login('me@me.com', 'p')
        user = User.users[0]
        with app.app_context():
            confirm_token = user.make_confirm_token()
        self.app.get('/auth/confirm/' + confirm_token)
        assert user.is_confirmed()
        
    def test_confirmWithBadToken(self):
        self._register('me@me.com', 'me', 'p')
        self._login('me@me.com', 'p')
        user = User.users[0]
        with app.app_context():
            token = user.make_confirm_token()
        self.app.get('/auth/confirm/' + '1' + token)
        assert not user.is_confirmed()
        
    def test_changeEmail(self):
        self._register('me@me.com', 'me', 'p')
        self._login('me@me.com', 'p')
        user = User.users[0]
        with app.app_context():
            token = user.make_change_email_token('newme@me.com')
        self.app.get('/auth/change-email/' + token)
        assert user.email == 'newme@me.com'
        
    def test_changeEmailWithBadPassword(self):
        self._register('me@me.com', 'me', 'p')
        self._login('me@me.com', 'p')
        r = self._post_form('/auth/change-email', {
            'email': 'newme@me.com',
            'password': 'q'
        })
        assert r.status_code == 200
        soup = BeautifulSoup(r.data)
        assert soup.find(class_ = 'flash-message').string == 'Invalid email or password.'
        
    def test_changePassword(self):
        self._register('me@me.com', 'me', 'p')
        self._login('me@me.com', 'p')
        r = self._post_form('/auth/change-password', {
            'old_password': 'p',
            'password': 'q',
            'password2': 'q'
        }, True)
        assert r.status_code == 200
        user = User.users[0]
        assert user.verify_password('q')

    def test_changePasswordWithBadPassword(self):
        self._register('me@me.com', 'me', 'p')
        self._login('me@me.com', 'p')
        r = self._post_form('/auth/change-password', {
            'old_password': 'q',
            'password': 'p',
            'password2': 'p'
        }, True)
        assert r.status_code == 200
        soup = BeautifulSoup(r.data)
        assert soup.find(class_ = 'flash-message').string == 'Invalid password.'
        user = User.users[0]
        assert user.verify_password('p')

    def test_changePasswordWithPasswordMismatch(self):
        self._register('me@me.com', 'me', 'p')
        self._login('me@me.com', 'p')
        r = self._post_form('/auth/change-password', {
            'old_password': 'p',
            'password': 'q',
            'password2': 'r'
        }, True)
        assert r.status_code == 200
        soup = BeautifulSoup(r.data)
        assert soup.find(class_ = 'flash-message').string == 'Invalid password.'
        user = User.users[0]
        assert user.verify_password('p')
        
    def test_logout(self):
        self._register('me@me.com', 'me', 'p')
        self._login('me@me.com', 'p')
        r = self.app.get('/loggedin')
        assert r.status_code == 200
        self.app.get('/auth/logout')
        r = self.app.get('/loggedin')
        assert r.status_code == 302
        
    def test_reset(self):
        self._register('me@me.com', 'me', 'p')
        r = self._post_form('/auth/reset', {
            'email': 'notme@me.com'
        })
        assert r.status_code == 302
        assert r.headers['Location'] == 'http://localhost/auth/login'
        user = User.users[0]
        with app.app_context():
            token = user.make_reset_token()
        r = self._post_form('/auth/reset/' + token, {
            'token': token,
            'email': 'me@me.com',
            'password': 'q',
            'password2': 'q'
        })
        assert r.status_code == 302
        assert r.headers['Location'] == 'http://localhost/'
        assert user.verify_password('q')
        
    def test_resetWithBadEmail(self):
        self._register('me@me.com', 'me', 'p')
        r = self._post_form('/auth/reset', {
            'email': 'notme@me.com'
        })
        assert r.status_code == 302
        assert r.headers['Location'] == 'http://localhost/auth/login'
       
    def test_rememberMe(self):
        self._register('me@me.com', 'me', 'p')
        r = self._login('me@me.com', 'p', True)
        token = None
        for h in r.headers:
            if h[0] == 'Set-Cookie':
                m = re.match(r'^remember_token=([^;]+)', h[1])
                if m:
                    token = m.group(1)
                    break
        assert token is not None
        self.app.get('/auth/logout')
        self.app.set_cookie('localhost', 'remember_token', token)
        r = self.app.get('/loggedin')
        assert r.data == 'loggedin'

    def test_refresh(self):
        self._register('me@me.com', 'me', 'p')
        r = self._login('me@me.com', 'p', True)
        token = None
        for h in r.headers:
            if h[0] == 'Set-Cookie':
                m = re.match(r'^remember_token=([^;]+)', h[1])
                if m:
                    token = m.group(1)
                    break
        assert token is not None
        self.app.get('/auth/logout')
        self.app.set_cookie('localhost', 'remember_token', token)
        r = self.app.get('/fresh')
        assert r.status_code == 302
        r = self._post_form('/auth/refresh', {
            'email': 'me@me.com',
            'password': 'p'
        }, True)
        assert r.status_code == 200
        r = self.app.get('/fresh')
        assert r.data == 'fresh'

if __name__ == '__main__':
    unittest.main()

