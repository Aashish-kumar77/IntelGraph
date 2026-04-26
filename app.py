"""
IntelGraph — Secure OSINT Mapping Engine
Hardened app.py — Security features:
  - Secret key loaded from environment variable (never hardcoded)
  - CSRF protection on all state-changing POST routes (Flask-WTF)
  - Rate limiting on login/register (Flask-Limiter)
  - Login brute-force lockout after 5 failed attempts (per user, resets on success)
  - Password strength enforcement (min 8 chars, mixed requirements)
  - Payload size cap on save_map (1 MB)
  - Security headers on every response (CSP, HSTS, X-Frame-Options, etc.)
  - Session timeout after 60 minutes of inactivity
  - Input length validation on all user-supplied fields
  - Admin action audit log (written to audit.log)
  - Registration can be closed by Super Admin via REGISTRATION_OPEN env var
  - debug=False enforced — only runs debug if FLASK_DEBUG env var is set
"""

import os
import re
import json
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, redirect, url_for, flash,
                   request, jsonify, session, make_response, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         login_required, logout_user, current_user)
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ─────────────────────────────────────────
#  App factory
# ─────────────────────────────────────────
app = Flask(__name__)

# ── Secret key: MUST be set via environment variable in production ──
# Generate a good one with: python3 -c "import secrets; print(secrets.token_hex(32))"
_secret = os.environ.get('INTELGRAPH_SECRET_KEY')
if not _secret:
    # Fallback for local dev only — print a warning so it's impossible to miss
    import secrets as _s
    _secret = _s.token_hex(32)
    print("\n[WARNING] INTELGRAPH_SECRET_KEY not set — using a random key.")
    print("[WARNING] Sessions will be lost on restart. Set the env var in production!\n")

app.config['SECRET_KEY'] = _secret
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///intelgraph.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ── Session security ──
app.config['SESSION_COOKIE_HTTPONLY'] = True   # JS cannot read the session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF mitigation
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('HTTPS', 'false').lower() == 'true'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)  # auto-expire after 60 min

# ── WTF CSRF ──
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token lifetime

# ── Payload limits ──
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB global request cap

# ── Registration control ──
# Set REGISTRATION_OPEN=false in env to lock registration once initial admin is set up
REGISTRATION_OPEN = os.environ.get('REGISTRATION_OPEN', 'true').lower() != 'false'

# ─────────────────────────────────────────
#  Extensions
# ─────────────────────────────────────────
db      = SQLAlchemy(app)
bcrypt  = Bcrypt(app)
csrf    = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Authentication required.'
login_manager.login_message_category = 'warning'

# Rate limiter — backs off with Redis if available, falls back to in-memory
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],          # no global limit; apply per-route
    storage_uri=os.environ.get('REDIS_URL', 'memory://'),
)

# ─────────────────────────────────────────
#  Audit logging
# ─────────────────────────────────────────
audit_logger = logging.getLogger('intelgraph.audit')
audit_logger.setLevel(logging.INFO)
_ah = logging.FileHandler('audit.log')
_ah.setFormatter(logging.Formatter('%(asctime)s  %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
audit_logger.addHandler(_ah)

def audit(action: str, detail: str = ''):
    who = current_user.username if current_user.is_authenticated else 'anon'
    ip  = request.remote_addr
    audit_logger.info(f'[{ip}] {who} | {action} | {detail}')

# ─────────────────────────────────────────
#  Security headers — applied to EVERY response
# ─────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Stop browsers sniffing MIME types
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Referrer info sent only on same-origin requests
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Permissions policy — deny camera/mic/geolocation
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # Basic CSP — allow only our own scripts + the two CDN libraries
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' "
        "https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://wsrv.nl https://www.google.com "
        "https://unavatar.io https://avatars.githubusercontent.com "
        "https://api.microlink.io; "
        "connect-src 'self' https://api.microlink.io https://wsrv.nl "
        "https://unavatar.io https://avatars.githubusercontent.com; "
        "frame-ancestors 'none';"
    )
    # HSTS — only send over HTTPS (enable when behind SSL)
    if os.environ.get('HTTPS', 'false').lower() == 'true':
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains')
    return response

# ─────────────────────────────────────────
#  Session activity timeout
# ─────────────────────────────────────────
@app.before_request
def enforce_session_timeout():
    if current_user.is_authenticated:
        last = session.get('_last_activity')
        now  = datetime.utcnow().timestamp()
        if last and (now - last) > 3600:   # 60 minutes
            logout_user()
            session.clear()
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        session['_last_activity'] = now
        session.permanent = True

# ─────────────────────────────────────────
#  Validation helpers
# ─────────────────────────────────────────
MAX_SAVE_BYTES = 1 * 1024 * 1024  # 1 MB per map save

def validate_username(username: str) -> str | None:
    """Return an error string, or None if valid."""
    if not username:
        return 'Username cannot be empty.'
    if len(username) < 3:
        return 'Username must be at least 3 characters.'
    if len(username) > 30:
        return 'Username cannot exceed 30 characters.'
    if not re.match(r'^[A-Za-z0-9_.-]+$', username):
        return 'Username may only contain letters, numbers, _ . and -'
    return None

def validate_password(password: str) -> str | None:
    """Return an error string, or None if valid."""
    if not password:
        return 'Password cannot be empty.'
    if len(password) < 8:
        return 'Password must be at least 8 characters.'
    if len(password) > 128:
        return 'Password is too long (max 128 characters).'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter.'
    if not re.search(r'[a-z]', password):
        return 'Password must contain at least one lowercase letter.'
    if not re.search(r'\d', password):
        return 'Password must contain at least one number.'
    return None

# ─────────────────────────────────────────
#  Database Models
# ─────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(30), unique=True, nullable=False)
    password_hash  = db.Column(db.String(128), nullable=False)
    is_admin       = db.Column(db.Boolean, default=False)
    is_locked      = db.Column(db.Boolean, default=False)       # manual admin lock
    failed_logins  = db.Column(db.Integer, default=0)           # consecutive failure counter
    locked_until   = db.Column(db.DateTime, nullable=True)      # timed cooldown expiry
    last_login_ip  = db.Column(db.String(45), nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    maps           = db.relationship('Map', backref='author', lazy=True)

class Map(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(120), nullable=False)
    created_at  = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    graph_data  = db.Column(db.Text, nullable=True, default='{}')
    is_deleted  = db.Column(db.Boolean, default=False)

# ─────────────────────────────────────────
#  Routes — Public
# ─────────────────────────────────────────
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per hour')   # max 10 registration attempts per IP per hour
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Allow first user even if registration is closed (bootstrapping)
    is_empty_db = User.query.count() == 0
    if not REGISTRATION_OPEN and not is_empty_db:
        flash('Registration is currently closed. Contact the administrator.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        err = validate_username(username)
        if err:
            flash(err, 'danger')
            return redirect(url_for('register'))

        err = validate_password(password)
        if err:
            flash(err, 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        is_first_user = is_empty_db
        user = User(username=username, password_hash=hashed_pw,
                    is_admin=is_first_user)
        db.session.add(user)
        db.session.commit()

        audit('REGISTER', f'new user: {username} | admin={is_first_user}')
        flash('Account created. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('30 per minute')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        # ── Step 1: Check manual admin lock BEFORE touching anything ──
        if user and user.is_locked and user.id != 1:
            audit('LOGIN_BLOCKED', f'locked account: {username}')
            flash('Your account has been locked by an administrator. Contact: <a href="mailto:thisisbasher@protonmail.com" style="color:#ff6b6b">thisisbasher@protonmail.com</a>', 'danger')
            return redirect(url_for('login'))

        # ── Step 2: Check timed cooldown BEFORE checking password ──
        if user and user.locked_until and user.locked_until > datetime.utcnow() and user.id != 1:
            remaining = int((user.locked_until - datetime.utcnow()).total_seconds())
            mins = remaining // 60
            secs = remaining % 60
            audit('LOGIN_COOLDOWN', f'{username} tried during cooldown ({remaining}s left)')
            if mins > 0:
                flash(f'Account on cooldown. Try again in {mins}m {secs}s.', 'danger')
            else:
                flash(f'Account on cooldown. Try again in {secs} seconds.', 'danger')
            return redirect(url_for('login'))

        # ── Step 3: Check password ──
        password_ok = False
        if user:
            try:
                password_ok = bcrypt.check_password_hash(user.password_hash, password)
            except ValueError:
                password_ok = False

        # ── Step 4a: Successful login ──
        if user and password_ok:
            user.failed_logins = 0
            user.locked_until  = None
            user.last_login_ip = request.remote_addr
            db.session.commit()
            login_user(user)
            session['_last_activity'] = datetime.utcnow().timestamp()
            audit('LOGIN_OK', f'{username} from {request.remote_addr}')
            flash(f'Welcome back, {user.username}.', 'success')
            nxt = request.args.get('next', '')
            if nxt and nxt.startswith('/') and not nxt.startswith('//'):
                return redirect(nxt)
            return redirect(url_for('dashboard'))

        # ── Step 4b: Failed login — progressive cooldown ──
        else:
            if user and user.id != 1:
                user.failed_logins = (user.failed_logins or 0) + 1
                fails = user.failed_logins

                # Schedule:
                # 1-2 fails  → plain wrong password message
                # 3rd fail   → warn: 1 more before cooldown
                # 4th fail   → 30 second cooldown
                # 6th fail   → 5 minute cooldown
                # 9th fail   → 15 minute cooldown
                # 12th fail  → 1 hour cooldown
                # 15th fail  → permanent lock (admin must unlock)

                if fails >= 15:
                    user.is_locked    = True
                    user.locked_until = None
                    db.session.commit()
                    audit('AUTO_LOCK', f'{username} permanently locked after {fails} failures')
                    flash('Account locked after too many failed attempts. Contact an administrator.', 'danger')
                    return redirect(url_for('login'))

                elif fails >= 12:
                    cooldown = 3600    # 1 hour
                elif fails >= 9:
                    cooldown = 900     # 15 minutes
                elif fails >= 6:
                    cooldown = 300     # 5 minutes
                elif fails >= 4:
                    cooldown = 30      # 30 seconds
                else:
                    cooldown = 0

                user.locked_until = (datetime.utcnow() + timedelta(seconds=cooldown)) if cooldown > 0 else None
                db.session.commit()

                audit('LOGIN_FAIL', f'{username} fail #{fails} from {request.remote_addr}')

                if cooldown > 0:
                    mins = cooldown // 60
                    secs = cooldown % 60
                    if mins > 0:
                        flash(f'Wrong password. Too many attempts — wait {mins}m {secs}s before trying again.', 'danger')
                    else:
                        flash(f'Wrong password. Too many attempts — wait {secs} seconds before trying again.', 'danger')
                elif fails == 3:
                    flash('Wrong password. One more failed attempt will trigger a cooldown.', 'warning')
                elif fails == 2:
                    flash('Wrong password. Please double-check your password.', 'warning')
                else:
                    flash('Wrong password.', 'danger')

            else:
                # User not found — don't reveal whether username exists
                audit('LOGIN_FAIL', f'unknown username from {request.remote_addr}')
                flash('Invalid credentials.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    audit('LOGOUT', '')
    session.pop('impersonator_id', None)
    session.pop('_last_activity', None)
    logout_user()
    return redirect(url_for('login'))


# ─────────────────────────────────────────
#  Routes — Authenticated User
# ─────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    user_maps = Map.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    return render_template('dashboard.html',
                           username=current_user.username, maps=user_maps)


@app.route('/create_map', methods=['POST'])
@login_required
def create_map():
    title = request.form.get('map_title', '').strip()
    if not title:
        flash('Map title cannot be empty.', 'danger')
        return redirect(url_for('dashboard'))
    if len(title) > 120:
        flash('Map title is too long (max 120 characters).', 'danger')
        return redirect(url_for('dashboard'))

    new_map = Map(title=title, user_id=current_user.id, graph_data='{}')
    db.session.add(new_map)
    db.session.commit()
    audit('CREATE_MAP', f'id={new_map.id} title="{title}"')
    return redirect(url_for('dashboard'))


@app.route('/map/<int:map_id>')
@login_required
def view_map(map_id):
    intel_map = Map.query.get_or_404(map_id)
    if intel_map.user_id != current_user.id and not current_user.is_admin:
        audit('ACCESS_DENIED', f'user tried to view map {map_id}')
        abort(403)
    if intel_map.is_deleted and not current_user.is_admin:
        abort(404)
    return render_template('editor.html', intel_map=intel_map)


@app.route('/save_map/<int:map_id>', methods=['POST'])
@login_required
def save_map(map_id):
    intel_map = Map.query.get_or_404(map_id)

    # Authorisation
    if intel_map.user_id != current_user.id and not current_user.is_admin:
        audit('SAVE_DENIED', f'map {map_id}')
        return jsonify({'success': False, 'error': 'Forbidden'}), 403

    # Size cap — prevent enormous payloads bloating the DB
    raw = request.data
    if len(raw) > MAX_SAVE_BYTES:
        return jsonify({'success': False,
                        'error': f'Payload too large (max {MAX_SAVE_BYTES // 1024} KB)'}), 413

    # Validate it is valid JSON before storing
    try:
        json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return jsonify({'success': False, 'error': 'Invalid JSON payload'}), 400

    intel_map.graph_data = raw.decode('utf-8')
    db.session.commit()
    return jsonify({'success': True})


@app.route('/delete_map/<int:map_id>', methods=['POST'])
@login_required
def delete_map(map_id):
    m = Map.query.get_or_404(map_id)
    if m.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    m.is_deleted = True
    db.session.commit()
    audit('DELETE_MAP', f'id={map_id} title="{m.title}"')
    if current_user.is_admin and m.user_id != current_user.id and 'impersonator_id' not in session:
        return redirect(url_for('admin_panel'))
    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────
#  Routes — Admin
# ─────────────────────────────────────────
def admin_required(f):
    """Decorator: 403 if current user is not admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            audit('ADMIN_ACCESS_DENIED', request.path)
            abort(403)
        return f(*args, **kwargs)
    return decorated


def superadmin_required(f):
    """Decorator: 403 if current user is not ID 1 (Super Admin)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            audit('SUPERADMIN_ACCESS_DENIED', request.path)
            abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    all_users    = User.query.all()
    active_maps  = Map.query.filter_by(is_deleted=False).all()
    deleted_maps = Map.query.filter_by(is_deleted=True).all()
    is_superadmin   = (current_user.id == 1)
    super_admin_user = User.query.get(1)
    super_admin_name = super_admin_user.username if super_admin_user else ''
    return render_template('admin.html',
                           users=all_users,
                           active_maps=active_maps,
                           deleted_maps=deleted_maps,
                           is_superadmin=is_superadmin,
                           super_admin_name=super_admin_name)


@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
@superadmin_required
def toggle_admin(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == 1:
        flash('Cannot alter Super Admin privileges.', 'danger')
        return redirect(url_for('admin_panel'))
    u.is_admin = not u.is_admin
    db.session.commit()
    status = 'granted' if u.is_admin else 'revoked'
    audit('TOGGLE_ADMIN', f'{u.username} → admin={u.is_admin}')
    flash(f'Admin privileges {status} for {u.username}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
@superadmin_required
def reset_password(user_id):
    u = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password', '')

    err = validate_password(new_password)
    if err:
        flash(f'Password reset failed: {err}', 'danger')
        return redirect(url_for('admin_panel'))

    u.password_hash   = bcrypt.generate_password_hash(new_password).decode('utf-8')
    u.failed_logins   = 0
    u.locked_until    = None
    u.is_locked       = False
    db.session.commit()
    audit('RESET_PASSWORD', f'target={u.username}')
    flash(f'Password for {u.username} has been reset.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/toggle_lock/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_lock(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == 1 or u.id == current_user.id:
        flash('Cannot lock this account.', 'danger')
        return redirect(url_for('admin_panel'))
    u.is_locked = not u.is_locked
    if not u.is_locked:
        u.failed_logins = 0
        u.locked_until  = None   # clear any timed cooldown too
    db.session.commit()
    status = 'locked' if u.is_locked else 'unlocked'
    audit('TOGGLE_LOCK', f'{u.username} → {status}')
    flash(f'{u.username} has been {status}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/impersonate/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def impersonate_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == current_user.id or u.id == 1:
        return redirect(url_for('admin_panel'))
    audit('IMPERSONATE_START', f'admin={current_user.username} → target={u.username}')
    session['impersonator_id'] = current_user.id
    login_user(u)
    return redirect(url_for('dashboard'))


@app.route('/admin/stop_impersonating')
@login_required
def stop_impersonating():
    if 'impersonator_id' in session:
        admin_user = User.query.get(session['impersonator_id'])
        if admin_user:
            audit('IMPERSONATE_STOP', f'returning to {admin_user.username}')
            login_user(admin_user)
            session.pop('impersonator_id', None)
            return redirect(url_for('admin_panel'))
    logout_user()
    return redirect(url_for('login'))


@app.route('/admin/restore_map/<int:map_id>', methods=['POST'])
@login_required
@admin_required
def restore_map(map_id):
    m = Map.query.get_or_404(map_id)
    m.is_deleted = False
    db.session.commit()
    audit('RESTORE_MAP', f'id={map_id}')
    return redirect(url_for('admin_panel'))


@app.route('/admin/hard_delete_map/<int:map_id>', methods=['POST'])
@login_required
@admin_required
def hard_delete_map(map_id):
    m = Map.query.get_or_404(map_id)
    db.session.delete(m)
    db.session.commit()
    audit('HARD_DELETE_MAP', f'id={map_id} title="{m.title}"')
    return redirect(url_for('admin_panel'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.is_admin and current_user.id != 1:
        flash('Only the Super Admin can delete other administrators.', 'danger')
        return redirect(url_for('admin_panel'))
    if u.id == current_user.id or u.id == 1:
        flash('Cannot delete this account.', 'danger')
        return redirect(url_for('admin_panel'))
    Map.query.filter_by(user_id=u.id).delete()
    db.session.delete(u)
    db.session.commit()
    audit('DELETE_USER', f'username={u.username}')
    flash(f'Account {u.username} deleted.', 'success')
    return redirect(url_for('admin_panel'))


# ─────────────────────────────────────────
#  Error handlers
# ─────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template('login.html',
                           error='Access denied. You do not have permission.'), 403

@app.errorhandler(404)
def not_found(e):
    return redirect(url_for('dashboard'))

@app.errorhandler(413)
def too_large(e):
    return jsonify({'success': False, 'error': 'Payload too large'}), 413

@app.errorhandler(429)
def rate_limited(e):
    flash('Too many attempts. Please wait before trying again.', 'danger')
    return redirect(url_for('login'))


# ─────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, port=5000)
