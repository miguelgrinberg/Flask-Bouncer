from flask import current_app, render_template, request, flash, redirect, url_for, session
from flask.ext.login import current_user, login_user, logout_user, confirm_login, login_required
from . import blueprint as bouncer
from .forms import BaseRegisterForm, RegisterForm, LoginForm, ResetRequestForm, ResetForm, ChangeEmailForm, ChangePasswordForm, RefreshForm
from .emails import send_email

def _cfg(key, default):
    return current_app.bouncer.get_config(key, default)
    
@bouncer.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = current_app.bouncer.user_class.find(email = form.email.data)
        if user:
            if user.verify_password(form.password.data):
                login_user(user, form.remember_me.data)
                return redirect(session.pop('next', None) or url_for('index'))
    if request.method == 'POST':
        flash(_cfg('flash.login_error', 'Invalid username or password.'), 'error')
    else:
        session['next'] = request.args.get('next')
    providers = {}
    for k in current_app.bouncer.get_oauth_providers():
        providers[k] = current_app.bouncer.get_oauth_provider(k)['display_name']
    return render_template('bouncer/login.html', form = form, providers = providers)

@bouncer.route('/refresh', methods = ['GET', 'POST'])
@login_required
def refresh():
    form = RefreshForm()
    if form.validate_on_submit():
        user = current_app.bouncer.user_class.find(email = form.email.data)
        if user:
            if user.verify_password(form.password.data):
                confirm_login()
                return redirect(session.pop('next', None) or url_for('index'))
    if request.method == 'POST':
        flash(_cfg('flash.login_error', 'Invalid username or password.'), 'error')
    else:
        session['next'] = request.args.get('next')
    providers = {}
    for k in current_app.bouncer.get_oauth_providers():
        providers[k] = current_app.bouncer.get_oauth_provider(k)['display_name']
    return render_template('bouncer/refresh.html', form = form, providers = providers)

@bouncer.route('/logout')
@login_required
def logout():
    logout_user()
    flash(_cfg('flash.logout_success', 'You have been logged out.'), 'success')
    return redirect(url_for('index'))

@bouncer.route('/register', methods = ['GET', 'POST'])
def register():
    if not current_user.is_anonymous():
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = current_app.bouncer.user_class(
            email = form.email.data,
            username = form.username.data,
            password = form.password.data
        )
        user.save()
        token = user.make_confirm_token()
        send_email('confirm', user, None, token = token)
        flash(_cfg('flash.register_success', 'A confirmation email has been sent to you.'), 'info')
        return redirect(url_for('index'))
    return render_template('bouncer/register.html', form = form)

@bouncer.route('/confirm')
@login_required
def confirm_request():
    if current_user.is_confirmed():
        return redirect(url_for('index'))
    token = current_user.make_confirm_token()
    send_email('confirm', current_user, None, token = token)
    flash(_cfg('flash.confirm_request_success', 'The confirmation email has been resent.'), 'info')
    return redirect(url_for('index'))
    
@bouncer.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.verify_confirm_token(token):
        current_user.save()
        flash(_cfg('flash.confirm_success', 'You have confirmed your email address.'), 'success')
    return redirect(url_for('index'))
    
@bouncer.route('/reset', methods = ['GET', 'POST'])
def reset_request():
    if not current_user.is_anonymous():
        return redirect(url_for('index'))
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = current_app.bouncer.user_class.find(email = form.email.data)
        if user:
            token = user.make_reset_token()
            user.save()
            send_email('reset', user, None, token = token)
        flash(_cfg('flash.reset_request_success', 'An email with instructions to reset your password has been sent.'), 'info')
        return redirect(url_for('.login'))
    return render_template('bouncer/reset_request.html', form = form)

@bouncer.route('/reset/<token>', methods = ['GET', 'POST'])
def reset(token):
    if not current_user.is_anonymous():
        return redirect(url_for('index'))
    form = ResetForm()
    if form.validate_on_submit():
        user = current_app.bouncer.user_class.find(email = form.email.data)
        if user and user.verify_reset_token(form.token.data):
            user.password = request.form['password']
            user.save()
            flash(_cfg('flash.reset_success', 'Your password has been updated.'), 'success')
            return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))
    form.token.data = token
    return render_template('bouncer/reset.html', form = form)

@bouncer.route('/change-email', methods = ['GET', 'POST'])
@login_required
def change_email_request():
    if current_user.is_social():
        return redirect(url_for('index'))
    form = ChangeEmailForm()
    if form.validate_on_submit():
        new_email = form.email.data
        if current_user.verify_password(form.password.data):
            token = current_user.make_change_email_token(new_email)
            current_user.save()
            send_email('change_email', current_user, new_email, token = token)
            flash(_cfg('flash.change_email_request_success', 'An email with instructions to confirm your new email address has been sent.'), 'info')
            return redirect(url_for('index'))
    if request.method == 'POST':
        flash(_cfg('flash.change_email_request_error', 'Invalid email or password.'), 'error')
    return render_template("bouncer/change_email.html", form = form)

@bouncer.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.is_social():
        return redirect(url_for('index'))
    if current_user.verify_change_email_token(token):
        current_user.save()
        flash(_cfg('flash.change_email_success', 'Your email address has been updated.'), 'success')
    return redirect(url_for('index'))

@bouncer.route('/change-password', methods = ['GET', 'POST'])
@login_required
def change_password():
    if current_user.is_social():
        return redirect(url_for('index'))
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            current_user.save()
            flash(_cfg('flash.change_password_success', 'Your password has been updated.'), 'success')
            return redirect(url_for('index'))
    if request.method == 'POST':
        flash(_cfg('flash.change_password_error', 'Invalid password.'), 'error')
    return render_template("bouncer/change_password.html", form = form)

@bouncer.route('/login/<provider>')
def oauth_login(provider):
    if not current_user.is_anonymous():
        return redirect(url_for('index'))
    p = current_app.bouncer.get_oauth_provider(provider)
    if not p:
        flash(_cfg('flash.invalid_operation', 'Invalid operation.'), 'error')
        return redirect(url_for('index'))
    if p['type'] == 'oauth1':
        request_token = p['service'].get_request_token(
            params = { 'oauth_callback': url_for('.oauth_authorized', provider = provider, _external = True) })
        session['request_token'] = request_token
        return redirect(p['service'].get_authorize_url(request_token[0]))
    elif p['type'] == 'oauth2':
        return redirect(p['service'].get_authorize_url(
            scope = p['scope'],
            response_type = 'code',
            redirect_uri = url_for('.oauth_authorized', provider = provider, _external = True)))
    else:
        session.pop('next', None)
        flash(_cfg('flash.invalid_operation', 'Invalid operation.'), 'error')
        return redirect(url_for('index'))

@bouncer.route('/refresh/<provider>')
def oauth_refresh(provider):
    if current_user.is_anonymous():
        return redirect(url_for('index'))
    p = current_app.bouncer.get_oauth_provider(provider)
    if not p:
        session.pop('next', None)
        flash(_cfg('flash.invalid_operation', 'Invalid operation.'), 'error')
        return redirect(url_for('index'))
    session['refresh'] = True
    if p['type'] == 'oauth1':
        request_token = p['service'].get_request_token(
            params = { 'oauth_callback': url_for('.oauth_authorized', provider = provider, _external = True) })
        session['request_token'] = request_token
        return redirect(p['service'].get_authorize_url(request_token[0]))
    elif p['type'] == 'oauth2':
        return redirect(p['service'].get_authorize_url(
            scope = p['scope'],
            response_type = 'code',
            redirect_uri = url_for('.oauth_authorized', provider = provider, _external = True)))
    else:
        session.pop('refresh', None)
        session.pop('next', None)
        flash(_cfg('flash.invalid_operation', 'Invalid operation.'), 'error')
        return redirect(url_for('index'))
        
@bouncer.route('/login/authorized/<provider>')
def oauth_authorized(provider):
    if not current_user.is_anonymous():
        return redirect(url_for('index'))
    refresh = session.pop('refresh', False)
    next = session.pop('next', None)
    p = current_app.bouncer.get_oauth_provider(provider)
    if not p:
        flash(_cfg('flash.invalid_operation', 'Invalid operation.'), 'error')
        return redirect(url_for('index'))
    social_id = None
    email = None
    username = None
    if p['type'] == 'oauth1':
        if 'oauth_verifier' in request.args:
            request_token = session.pop('request_token')
            oauth_session = p['service'].get_auth_session(
                request_token[0],
                request_token[1],
                data = { 'oauth_verifier': request.args['oauth_verifier'] })
            if provider == 'twitter':
                me = oauth_session.get('account/verify_credentials.json').json()
                social_id = 'twitter$@' + me.get('screen_name')
                username = me.get('screen_name')
    elif p['type'] == 'oauth2':
        if not 'code' in request.args:
            flash(_cfg('flash.authentication_failed', 'Authentication failed.'), 'error')
            return redirect(url_for('index'))
        oauth_session = p['service'].get_auth_session(data = { 
            'code': request.args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': url_for('.oauth_authorized', provider = provider, _external = True)
        }, decoder = p.get('decoder'))
        if provider == 'facebook':
            me = oauth_session.get('me').json()
            social_id = 'facebook$' + me.get('link')
            email = me.get('email')
            username = me.get('username')
        elif provider == 'google':
            me = oauth_session.get('userinfo').json()
            social_id = 'google$' + me.get('id')
            email = me.get('email')
            username = me.get('name').lower().replace(' ', '_')
    else:
        flash(_cfg('flash.invalid_operation', 'Invalid operation.'), 'error')
        return redirect(url_for('index'))
    if social_id is None:
        flash(_cfg('flash.invalid_operation', 'Invalid operation.'), 'error')
        return redirect(url_for('index'))
    user = current_app.bouncer.user_class.find(social_id = social_id)    
    if user is None: 
        if not refresh:
            session['new_account'] = {
                'social_id': social_id,
                'email': email,
                'username': username
            }        
            return redirect(url_for('.create_account'))
        else:
            flash(_cfg('flash.authentication_failed', 'Authentication failed.'), 'error')
            return redirect(url_for('index'))
    else:
        if refresh:
            confirm_login()
        else:
            login_user(user, True)
        return redirect(next or url_for('index'))
        
@bouncer.route('/create_account', methods = ['GET', 'POST'])
def create_account():
    if not current_user.is_anonymous():
        return redirect(url_for('index'))
    new_account = session.pop('new_account', None)
    if new_account is None:
        return redirect(url_for('index'))
    if not current_user.is_anonymous():
        return redirect(url_for('index'))
    social_id = new_account.get('social_id')
    if social_id is None:
        return redirect(url_for('index'))
    form = BaseRegisterForm()
    if form.validate_on_submit():
        user = current_app.bouncer.user_class(
            email = form.email.data,
            username = form.username.data,
            social_id = social_id
        )
        if user.email == new_account.get('email'):
            user.confirmed = True
        user.save()
        if not user.confirmed:
            token = user.make_confirm_token()
            send_email('confirm', user, None, token = token)
            flash(_cfg('flash.register_success', 'A confirmation email has been sent to you.'), 'info')
        login_user(user, True)
        return redirect(url_for('index'))
    session['new_account'] = new_account
    if request.method == 'GET':
        form.email.data = session['new_account'].get('email') or ''
        form.username.data = session['new_account'].get('username') or ''
    return render_template('bouncer/register_social.html', form = form)
