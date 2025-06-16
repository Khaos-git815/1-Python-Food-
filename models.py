from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from extensions import db
import re
import pyotp
import json
import secrets
import hashlib
import requests

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expires = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Login attempt tracking
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # Two-factor authentication
    two_factor_secret = db.Column(db.String(32))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    backup_codes = db.Column(db.Text)  # JSON string of hashed backup codes
    
    # Session management
    active_sessions = db.Column(db.Text, default='[]')  # JSON string of active sessions
    last_security_notification = db.Column(db.DateTime)
    
    saved_recipes = db.relationship('SavedRecipe', backref='user', lazy=True)

    def set_password(self, password):
        if not self._is_password_strong(password):
            raise ValueError("Password does not meet strength requirements")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def _is_password_strong(self, password):
        """
        Check if password meets strength requirements:
        - At least 8 characters long
        - Contains at least one uppercase letter
        - Contains at least one lowercase letter
        - Contains at least one number
        - Contains at least one special character
        """
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True

    def increment_login_attempts(self):
        self.login_attempts += 1
        if self.login_attempts >= 5:  # Lock after 5 failed attempts
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)  # Lock for 30 minutes
        db.session.commit()

    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None
        db.session.commit()

    def is_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        if self.locked_until and datetime.utcnow() >= self.locked_until:
            self.reset_login_attempts()
        return False

    def get_lockout_time(self):
        if self.locked_until:
            remaining = self.locked_until - datetime.utcnow()
            return max(0, int(remaining.total_seconds() / 60))
        return 0

    def generate_verification_token(self):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        self.verification_token = serializer.dumps(self.email, salt='email-verification')
        return self.verification_token

    def verify_email(self, token):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = serializer.loads(token, salt='email-verification', max_age=3600)  # 1 hour expiry
            if email == self.email:
                self.is_verified = True
                self.verification_token = None
                return True
        except:
            pass
        return False

    def generate_reset_token(self):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        self.reset_token = serializer.dumps(self.email, salt='password-reset')
        self.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
        return self.reset_token

    def verify_reset_token(self, token):
        if not self.reset_token or not self.reset_token_expires:
            return False
        if datetime.utcnow() > self.reset_token_expires:
            return False
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = serializer.loads(token, salt='password-reset')
            if email == self.email:
                return True
        except:
            pass
        return False

    def update_last_login(self):
        self.last_login = datetime.utcnow()
        self.reset_login_attempts()  # Reset login attempts on successful login

    # Two-factor authentication methods
    def enable_2fa(self):
        if not self.two_factor_secret:
            self.two_factor_secret = pyotp.random_base32()
        self.two_factor_enabled = True
        self.generate_backup_codes()
        db.session.commit()
        return self.two_factor_secret

    def disable_2fa(self):
        self.two_factor_secret = None
        self.two_factor_enabled = False
        self.backup_codes = None
        db.session.commit()

    def verify_2fa(self, token):
        if not self.two_factor_enabled or not self.two_factor_secret:
            return False
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(token)

    def get_2fa_uri(self):
        if not self.two_factor_secret:
            return None
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.provisioning_uri(
            name=self.email,
            issuer_name='FlavorNest'
        )

    def generate_backup_codes(self):
        """Generate 10 backup codes for 2FA recovery"""
        codes = []
        for _ in range(10):
            code = secrets.token_hex(4)  # 8 characters
            hashed_code = hashlib.sha256(code.encode()).hexdigest()
            codes.append(hashed_code)
        self.backup_codes = json.dumps(codes)
        return codes

    def verify_backup_code(self, code):
        """Verify a backup code and remove it if valid"""
        if not self.backup_codes:
            return False
        
        hashed_code = hashlib.sha256(code.encode()).hexdigest()
        codes = json.loads(self.backup_codes)
        
        if hashed_code in codes:
            codes.remove(hashed_code)
            self.backup_codes = json.dumps(codes)
            db.session.commit()
            return True
        return False

    # Session management methods
    def add_session(self, session_id, user_agent, ip_address):
        sessions = self.get_active_sessions()
        sessions.append({
            'id': session_id,
            'user_agent': user_agent,
            'ip_address': ip_address,
            'created_at': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'location': self._get_location_from_ip(ip_address)
        })
        self.active_sessions = json.dumps(sessions)
        db.session.commit()

    def remove_session(self, session_id):
        sessions = self.get_active_sessions()
        sessions = [s for s in sessions if s['id'] != session_id]
        self.active_sessions = json.dumps(sessions)
        db.session.commit()

    def get_active_sessions(self):
        try:
            return json.loads(self.active_sessions)
        except:
            return []

    def update_session_activity(self, session_id):
        sessions = self.get_active_sessions()
        for session in sessions:
            if session['id'] == session_id:
                session['last_activity'] = datetime.utcnow().isoformat()
                break
        self.active_sessions = json.dumps(sessions)
        db.session.commit()

    def _get_location_from_ip(self, ip_address):
        """Get location information from IP address"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}')
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'city': data.get('city'),
                        'isp': data.get('isp')
                    }
        except:
            pass
        return None

    def delete_account(self):
        # Delete all saved recipes
        SavedRecipe.query.filter_by(user_id=self.id).delete()
        # Delete the user
        db.session.delete(self)
        db.session.commit()

class SavedRecipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipe_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    image = db.Column(db.String(500))
    saved_at = db.Column(db.DateTime, default=datetime.utcnow) 