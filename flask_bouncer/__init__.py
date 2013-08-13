import json
from marrow.util.bunch import Bunch
from flask import current_app
from flask.ext.login import LoginManager, current_user, login_required, fresh_login_required
from rauth import OAuth1Service, OAuth2Service
from rauth.utils import parse_utf8_qsl
from .bouncer import blueprint as bouncer_blueprint
from .user_auth_mixin import UserAuthMixin

class Bouncer():
    def __init__(self, app = None, user_class = None, url_prefix = '/auth'):
        if app is not None:
            self.init_app(app, user_class, url_prefix)
        
    def init_app(self, app, user_class, url_prefix = '/auth'):
        config = Bunch(app.config.get('BOUNCER_CONFIG') or {})
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['bouncer'] = config

        if not hasattr(self, 'login_manager'):
            self.login_manager = LoginManager()
        self.login_manager.init_app(app)
        self.login_manager.user_loader(user_class.get)
        self.login_manager.login_view = 'bouncer.login'
        if getattr(config, 'flash.login_message', None):
            self.login_manager.login_message = getattr(config.flash.login_message)
        self.login_manager.refresh_view = 'bouncer.refresh'
        if getattr(config, 'flash.refresh_message', None):
            self.login_manager.needs_refresh_message = getattr(config.flash.refresh_message)
        self.login_manager.session_protection = "strong"
        
        self.user_class = user_class
        print bouncer_blueprint
        app.register_blueprint(bouncer_blueprint, url_prefix = url_prefix)
        app.bouncer = self

        app.oauth_providers = {}
        if hasattr(config, 'oauth'):
            oauth = config.oauth
            if hasattr(oauth, 'facebook'):
                app.oauth_providers['facebook'] = self._configure_facebook_oauth(oauth.facebook)
            if hasattr(oauth, 'twitter'):
                app.oauth_providers['twitter'] = self._configure_twitter_oauth(oauth.twitter)
            if hasattr(oauth, 'google'):
                app.oauth_providers['google'] = self._configure_google_oauth(oauth.google)

    def get_config(self, key, default = None):
        return getattr(current_app.extensions['bouncer'], key, default)
        
    def get_oauth_provider(self, provider):
        return current_app.oauth_providers.get(provider)
                        
    def get_oauth_providers(self):
        return current_app.oauth_providers
        
    def _configure_facebook_oauth(self, config):
        key = config['consumer_key']
        secret = config['consumer_secret']
        return {
            'type': 'oauth2',
            'display_name': 'Facebook',
            'service': OAuth2Service(
                client_id = key,
                client_secret = secret,
                name = 'facebook',
                authorize_url = 'https://graph.facebook.com/oauth/authorize',
                access_token_url = 'https://graph.facebook.com/oauth/access_token',
                base_url = 'https://graph.facebook.com/'),
            'scope': 'email',
            'decoder': parse_utf8_qsl
        }
        
    def _configure_twitter_oauth(self, config):
        key = config['consumer_key']
        secret = config['consumer_secret']
        return {
            'type': 'oauth1',
            'display_name': 'Twitter',
            'service': OAuth1Service(
                consumer_key = key,
                consumer_secret= secret,
                name = 'twitter',
                access_token_url = 'https://api.twitter.com/oauth/access_token',
                authorize_url = 'https://api.twitter.com/oauth/authorize',
                request_token_url = 'https://api.twitter.com/oauth/request_token',
                base_url = 'https://api.twitter.com/1.1/'),
            'scope': 'email',
            'decoder': parse_utf8_qsl
        }
        
    def _configure_google_oauth(self, config):
        key = config['consumer_key']
        secret = config['consumer_secret']
        return {
            'type': 'oauth2',
            'display_name': 'Google',
            'service': OAuth2Service(
                client_id = key,
                client_secret = secret,
                name = 'google',
                authorize_url = 'https://accounts.google.com/o/oauth2/auth',
                access_token_url = 'https://accounts.google.com/o/oauth2/token',
                base_url = 'https://www.googleapis.com/oauth2/v1/'),
            'scope': 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
            'decoder': json.loads
        }
