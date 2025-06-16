from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, SavedRecipe
from forms import (
    LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm,
    TwoFactorForm, BackupCodeForm, ChangePasswordForm, DeleteAccountForm
)
import requests
import os
from dotenv import load_dotenv
from whitenoise import WhiteNoise
from datetime import timedelta, datetime
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import qrcode
import io
import base64
import pyotp
import json
from extensions import db

# Load environment variables
load_dotenv()
API_KEY = os.getenv("SPOONACULAR_API_KEY")
app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Session expires after 7 days
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)  # Remember me cookie lasts 30 days
app.config['REMEMBER_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookie

# Rate Limiting Configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@flavornest.com')

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///flavornest.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,  # Enable connection health checks
    'pool_recycle': 300,    # Recycle connections after 5 minutes
}

# Configure WhiteNoise for static files
app.wsgi_app = WhiteNoise(app.wsgi_app, root='static/')

# Initialize database and login manager
db.init_app(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Spoonacular API configuration
SPOONACULAR_API_KEY = os.getenv('SPOONACULAR_API_KEY')
if not SPOONACULAR_API_KEY:
    raise ValueError("SPOONACULAR_API_KEY environment variable is not set. Please add it to your .env file.")
SPOONACULAR_BASE_URL = 'https://api.spoonacular.com/recipes'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
def init_db():
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(email='admin@flavornest.com').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@flavornest.com',
                is_admin=True
            )
            admin.set_password('Admin@123')  # Changed default password
            db.session.add(admin)
            db.session.commit()

# Initialize database on startup
init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/recipes', methods=['GET', 'POST'])
def recipes():
    query = request.form.get('query') if request.method == 'POST' else request.args.get('query', '')
    recipes = []
    
    try:
        if query:
            # Search for recipes based on query
            response = requests.get(
                f'{SPOONACULAR_BASE_URL}/complexSearch',
                params={
                    'apiKey': SPOONACULAR_API_KEY,
                    'query': query,
                    'number': 12,
                    'addRecipeInformation': True,
                    'fillIngredients': True,
                    'instructionsRequired': True,
                    'sort': 'popularity',
                    'sortDirection': 'desc'
                }
            )
            response.raise_for_status()
            recipes = response.json().get('results', [])
        else:
            # Get random recipes if no query
            response = requests.get(
                f'{SPOONACULAR_BASE_URL}/random',
                params={
                    'apiKey': SPOONACULAR_API_KEY,
                    'number': 12,
                    'addRecipeInformation': True,
                    'fillIngredients': True,
                    'instructionsRequired': True
                }
            )
            response.raise_for_status()
            recipes = response.json().get('recipes', [])
        
        return render_template('recipes.html', recipes=recipes, query=query)
    except requests.exceptions.RequestException as e:
        flash('Error fetching recipes. Please try again later.', 'error')
        return render_template('recipes.html', recipes=[], query=query)

@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    try:
        response = requests.get(
            f'{SPOONACULAR_BASE_URL}/{recipe_id}/information',
            params={'apiKey': SPOONACULAR_API_KEY}
        )
        response.raise_for_status()
        recipe = response.json()
        
        is_saved = False
        if current_user.is_authenticated:
            is_saved = SavedRecipe.query.filter_by(
                user_id=current_user.id,
                recipe_id=recipe_id
            ).first() is not None
        
        return render_template('recipe_detail.html', recipe=recipe, is_saved=is_saved)
    except requests.exceptions.RequestException as e:
        flash('Error fetching recipe details. Please try again later.', 'error')
        return redirect(url_for('recipes'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and user.is_locked():
            minutes = user.get_lockout_time()
            flash(f'Account is locked. Please try again in {minutes} minutes.', 'error')
            return redirect(url_for('login'))
        
        if user and user.check_password(form.password.data):
            if not user.is_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            
            if user.two_factor_enabled:
                session['user_id'] = user.id
                session['remember_me'] = form.remember_me.data
                return redirect(url_for('verify_2fa'))
            
            login_user(user, remember=form.remember_me.data)
            user.update_last_login()
            user.add_session(
                session_id=session.sid,
                user_agent=request.user_agent.string,
                ip_address=request.remote_addr
            )
            db.session.commit()
            
            # Send security notification
            send_security_notification(
                user,
                'New Login Detected',
                'new_login',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                timestamp=datetime.utcnow()
            )
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        
        if user:
            user.increment_login_attempts()
            if user.is_locked():
                flash('Too many failed attempts. Account is locked for 30 minutes.', 'error')
            else:
                flash('Invalid email or password', 'error')
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('auth/login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(
                username=form.username.data,
                email=form.email.data
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            send_verification_email(user)
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
        except ValueError as e:
            flash(str(e), 'error')
    
    return render_template('auth/register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/save_recipe/<int:recipe_id>', methods=['POST'])
@login_required
def save_recipe(recipe_id):
    # Check if recipe is already saved
    existing_save = SavedRecipe.query.filter_by(
        user_id=current_user.id,
        recipe_id=recipe_id
    ).first()
    
    if existing_save:
        flash('Recipe is already saved!', 'info')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))
    
    response = requests.get(
        f'{SPOONACULAR_BASE_URL}/{recipe_id}/information',
        params={'apiKey': SPOONACULAR_API_KEY}
    )
    recipe = response.json()
    
    saved_recipe = SavedRecipe(
        user_id=current_user.id,
        recipe_id=recipe_id,
        title=recipe['title'],
        image=recipe['image']
    )
    db.session.add(saved_recipe)
    db.session.commit()
    flash('Recipe saved successfully!', 'success')
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

@app.route('/saved_recipes')
@login_required
def saved_recipes():
    saved_recipes = SavedRecipe.query.filter_by(user_id=current_user.id).all()
    return render_template('saved_recipes.html', saved_recipes=saved_recipes)

@app.route('/unsave_recipe/<int:recipe_id>', methods=['POST'])
@login_required
def unsave_recipe(recipe_id):
    saved_recipe = SavedRecipe.query.filter_by(
        user_id=current_user.id,
        recipe_id=recipe_id
    ).first()
    
    if saved_recipe:
        db.session.delete(saved_recipe)
        db.session.commit()
        flash('Recipe removed from saved recipes', 'success')
    else:
        flash('Recipe was not saved', 'error')
    
    return redirect(url_for('saved_recipes'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_reset_password_email(user, token)
        flash('Check your email for instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('auth/reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.verify_reset_token(token):
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('reset_password_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            user.set_password(form.password.data)
            user.reset_token = None
            user.reset_token_expires = None
            db.session.commit()
            flash('Your password has been reset.', 'success')
            return redirect(url_for('login'))
        except ValueError as e:
            flash(str(e), 'error')
    return render_template('auth/reset_password.html', form=form)

@app.route('/verify_email/<token>')
def verify_email(token):
    if current_user.is_authenticated:
        if current_user.verify_email(token):
            db.session.commit()
            flash('Your email has been verified!', 'success')
        else:
            flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    form = TwoFactorForm()
    backup_form = BackupCodeForm()
    
    if form.validate_on_submit():
        if user.verify_2fa_token(form.token.data):
            login_user(user, remember=session.get('remember_me', False))
            user.update_last_login()
            user.add_session(
                session_id=session.sid,
                user_agent=request.user_agent.string,
                ip_address=request.remote_addr
            )
            db.session.commit()
            
            # Send security notification
            send_security_notification(
                user,
                '2FA Login Successful',
                '2fa_login',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                timestamp=datetime.utcnow()
            )
            
            session.pop('user_id', None)
            session.pop('remember_me', None)
            return redirect(url_for('home'))
        else:
            flash('Invalid authentication code.', 'danger')
    
    if backup_form.validate_on_submit():
        if user.verify_backup_code(backup_form.code.data):
            login_user(user, remember=session.get('remember_me', False))
            user.update_last_login()
            user.add_session(
                session_id=session.sid,
                user_agent=request.user_agent.string,
                ip_address=request.remote_addr
            )
            db.session.commit()
            
            # Send security notification
            send_security_notification(
                user,
                'Backup Code Used',
                'backup_code_used',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                timestamp=datetime.utcnow()
            )
            
            session.pop('user_id', None)
            session.pop('remember_me', None)
            return redirect(url_for('home'))
        else:
            flash('Invalid backup code.', 'danger')
    
    return render_template('auth/verify_2fa.html', form=form, backup_form=backup_form)

@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.two_factor_enabled:
        flash('Two-factor authentication is already enabled', 'info')
        return redirect(url_for('account_settings'))
    
    if request.method == 'POST':
        secret = current_user.enable_2fa()
        return redirect(url_for('show_2fa_qr'))
    
    return render_template('auth/setup_2fa.html')

@app.route('/show-2fa-qr')
@login_required
def show_2fa_qr():
    if not current_user.two_factor_enabled:
        return redirect(url_for('setup_2fa'))
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(current_user.get_2fa_uri())
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('auth/show_2fa_qr.html', qr_code=qr_code)

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    if not current_user.two_factor_enabled:
        flash('Two-factor authentication is not enabled', 'info')
        return redirect(url_for('account_settings'))
    
    current_user.disable_2fa()
    flash('Two-factor authentication has been disabled', 'success')
    return redirect(url_for('account_settings'))

@app.route('/account/settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    password_form = ChangePasswordForm()
    delete_form = DeleteAccountForm()
    
    if password_form.validate_on_submit():
        if current_user.check_password(password_form.current_password.data):
            try:
                current_user.set_password(password_form.new_password.data)
                db.session.commit()
                flash('Password has been updated', 'success')
            except ValueError as e:
                flash(str(e), 'error')
        else:
            flash('Current password is incorrect', 'error')
    
    if delete_form.validate_on_submit():
        if current_user.check_password(delete_form.password.data):
            current_user.delete_account()
            logout_user()
            flash('Your account has been deleted', 'success')
            return redirect(url_for('home'))
        else:
            flash('Password is incorrect', 'error')
    
    return render_template('account/settings.html',
                         password_form=password_form,
                         delete_form=delete_form)

@app.route('/account/sessions')
@login_required
def account_sessions():
    sessions = current_user.get_active_sessions()
    return render_template('account/sessions.html', sessions=sessions)

@app.route('/account/sessions/<session_id>/delete', methods=['POST'])
@login_required
def delete_session(session_id):
    current_user.remove_session(session_id)
    if session_id == session.sid:
        logout_user()
        flash('You have been logged out', 'info')
        return redirect(url_for('login'))
    flash('Session has been terminated', 'success')
    return redirect(url_for('account_sessions'))

@app.route('/favorites/<int:recipe_id>/delete', methods=['POST'])
@login_required
def delete_favorite(recipe_id):
    saved_recipe = SavedRecipe.query.filter_by(
        user_id=current_user.id,
        recipe_id=recipe_id
    ).first_or_404()
    
    db.session.delete(saved_recipe)
    db.session.commit()
    
    flash('Recipe removed from favorites.', 'success')
    return redirect(url_for('favorites'))

def send_reset_password_email(user, token):
    msg = Message('Reset Your Password',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email.
'''
    mail.send(msg)

def send_verification_email(user):
    token = user.generate_verification_token()
    msg = Message('Verify Your Email',
                  recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}

If you did not create an account then simply ignore this email.
'''
    mail.send(msg)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Run the app
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 