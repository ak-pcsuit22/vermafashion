from flask import Flask, render_template, redirect, url_for, request, flash, abort, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from datetime import datetime, timedelta
import os
import requests
import re
import smtplib
import ssl
import random
import string

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system environment

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# Load sensitive configuration from environment where possible
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret-for-prod')
# Allow overriding the database URL via env (use production DB in production)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'app.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Upload folder should be inside static but outside version control in production
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', os.path.join(BASE_DIR, 'static', 'uploads'))
# Limit upload size (default no limit) - set MAX_CONTENT_LENGTH in .env to limit in bytes
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 0)) or None  # 0 or not set = no limit
# Session / cookie security flags
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '0') in ('1', 'true', 'True')
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
# Minimum order enforcement (amount in currency units, and optional minimum item count)
app.config['MIN_ORDER_AMOUNT'] = int(os.environ.get('MIN_ORDER_AMOUNT', '500'))
app.config['MIN_ORDER_MIN_ITEMS'] = int(os.environ.get('MIN_ORDER_MIN_ITEMS', '4'))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Optional security middleware: Talisman for headers, CSRF for forms
try:
    from flask_talisman import Talisman
    # Minimal Content Security Policy; adjust for external resources you use
    csp = {
        'default-src': "'self'",
        'img-src': "'self' data:",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline' fonts.googleapis.com",
        'font-src': "fonts.gstatic.com"
    }
    Talisman(app, content_security_policy=csp)
except Exception:
    # flask_talisman is optional for development; install in production
    pass

try:
    from flask_wtf import CSRFProtect
    csrf = CSRFProtect(app)
except Exception:
    # CSRF protection is recommended; install Flask-WTF to enable it
    csrf = None


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product = db.Column(db.String(200), nullable=False)
    # optional normalized product reference
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    quantity = db.Column(db.Integer, default=1)
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # order contact/shipping info (may be null for older orders)
    name = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(60), nullable=True)
    address = db.Column(db.Text, nullable=True)
    # broken out address fields
    house_no = db.Column(db.String(120), nullable=True)
    street = db.Column(db.String(200), nullable=True)
    block = db.Column(db.String(120), nullable=True)
    village = db.Column(db.String(200), nullable=True)
    city = db.Column(db.String(120), nullable=True)
    state = db.Column(db.String(120), nullable=True)
    zipcode = db.Column(db.String(60), nullable=True)
    # admin provided reject reason
    reject_reason = db.Column(db.Text, nullable=True)
    messages = db.relationship('Message', backref='order', lazy=True)

    # relationship to product for convenience
    product_obj = db.relationship('Product', foreign_keys=[product_id])


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    sender = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    code = db.Column(db.String(32), nullable=False)
    purpose = db.Column(db.String(32), nullable=False)  # 'verify' or 'reset'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False, default=0.0)
    image_filename = db.Column(db.String(300), nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='cart_items')
    product = db.relationship('Product')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_now():
    # provide current year and cart count for templates
    count = 0
    try:
        if current_user.is_authenticated:
            # try DB-backed cart first
            try:
                total = db.session.query(db.func.sum(CartItem.quantity)).filter(CartItem.user_id == current_user.id).scalar()
                count = int(total or 0)
            except Exception:
                # fallback to session-based cart
                cart = session.get('cart', {})
                count = sum(int(q) for q in cart.values()) if cart else 0
        else:
            cart = session.get('cart', {})
            count = sum(int(q) for q in cart.values()) if cart else 0
    except Exception:
        count = 0
    return {'current_year': datetime.utcnow().year, 'cart_count': int(count)}


def create_tables():
    """Create database tables in a way that works across Flask versions.

    Some Flask versions or installations may not expose the
    `before_first_request` decorator on the `Flask` object. Creating
    tables explicitly using `app.app_context()` is compatible and
    safe to call at startup.
    """
    with app.app_context():
        # ensure upload folder exists
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        except Exception:
            pass
        db.create_all()

        # Add missing columns for existing DBs (simple migration)
        # Example: add `quantity` column to `product` if it doesn't exist yet.
        try:
            db_path = os.path.join(BASE_DIR, 'app.db')
            if os.path.exists(db_path):
                import sqlite3
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute("PRAGMA table_info(product);")
                cols = [r[1] for r in cur.fetchall()]
                if 'quantity' not in cols:
                    cur.execute("ALTER TABLE product ADD COLUMN quantity INTEGER NOT NULL DEFAULT 0;")
                    conn.commit()
                # ensure user table has is_verified
                cur.execute("PRAGMA table_info(user);")
                user_cols = [r[1] for r in cur.fetchall()]
                if 'is_verified' not in user_cols:
                    try:
                        cur.execute("ALTER TABLE user ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0;")
                        conn.commit()
                    except Exception:
                        pass
                # ensure orders table has columns for normalization and full address components
                cur.execute("PRAGMA table_info('order');")
                order_cols = [r[1] for r in cur.fetchall()]
                needed = {
                    'product_id': 'INTEGER',
                    'name': 'TEXT',
                    'phone': 'TEXT',
                    'address': 'TEXT',
                    'house_no': 'TEXT',
                    'street': 'TEXT',
                    'block': 'TEXT',
                    'village': 'TEXT',
                    'city': 'TEXT',
                    'state': 'TEXT',
                    'zipcode': 'TEXT',
                    'reject_reason': 'TEXT'
                }
                for col_name, col_def in needed.items():
                    if col_name not in order_cols:
                        try:
                            cur.execute(f"ALTER TABLE 'order' ADD COLUMN {col_name} {col_def};")
                            conn.commit()
                        except Exception:
                            # ignore failures - migration best-effort for dev env
                            pass
                cur.close()
                conn.close()
        except Exception:
            # don't block startup if migration step fails
            pass


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))


def send_email(subject, body, to_email):
    """Send email using SMTP config from environment. Falls back to printing to console if not configured."""
    smtp_server = os.environ.get('SMTP_SERVER')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_user = os.environ.get('SMTP_USERNAME')
    smtp_pass = os.environ.get('SMTP_PASSWORD')
    from_addr = os.environ.get('ADMIN_EMAIL', 'fashion.vistashop@gmail.com')

    # Development fallback: if SMTP not configured just print to console (safe)
    if not smtp_server or not smtp_user or not smtp_pass:
        print(f"--- EMAIL (dev) to: {to_email} ---\nSubject: {subject}\n{body}\n")
        return True

    try:
        from email.message import EmailMessage
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = to_email
        msg.set_content(body)

        context = ssl.create_default_context()
        smtp_debug = os.environ.get('SMTP_DEBUG', '0') in ('1', 'true', 'True')

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if smtp_debug:
                server.set_debuglevel(1)
            # Start TLS if requested
            if os.environ.get('SMTP_USE_TLS', '1') in ('1', 'true', 'True'):
                server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True
    except Exception as e:
        # Detailed error for debugging — printed to console only
        print('Email send failed (exception):', repr(e))
        return False


def create_and_send_otp(email, purpose='verify', user_id=None, ttl_minutes=15):
    """Create OTP and send via email. Logs success/failure to console."""
    try:
        code = _generate_otp(6)
        now = datetime.utcnow()
        otp = OTP(email=email, user_id=user_id, code=code, purpose=purpose, created_at=now, expires_at=now + timedelta(minutes=ttl_minutes))
        db.session.add(otp)
        db.session.commit()
        
        subject = 'Your verification code' if purpose == 'verify' else 'Your password reset code'
        body = f"Your { 'verification' if purpose=='verify' else 'password reset' } code is: {code}\nThis code expires in {ttl_minutes} minutes."
        
        print(f"[OTP] Generated code '{code}' for {email} (purpose={purpose})")
        
        success = send_email(subject, body, email)
        if success:
            print(f"[OTP] Email sent successfully to {email}")
        else:
            print(f"[OTP] Email send failed for {email}")
        
        return otp
    except Exception as e:
        print(f"[OTP] Error creating/sending OTP: {repr(e)}")
        raise


def parse_address_string(addr):
    """Best-effort parse of a freeform address string into components.
    Returns dict with keys: house_no, street, block, village, city, state, zipcode
    This is heuristic and intended for convenience only.
    """
    if not addr:
        return {}
    parts = [p.strip() for p in addr.split(',') if p.strip()]
    out = {k: None for k in ('house_no', 'street', 'block', 'village', 'city', 'state', 'zipcode')}
    if not parts:
        return out
    # try to extract zipcode if last part contains digits
    if re.search(r'\d', parts[-1]):
        out['zipcode'] = parts[-1]
        parts = parts[:-1]
    # remove trailing country if present
    if parts and parts[-1].lower() in ('india', 'usa', 'united states', 'united kingdom', 'uk'):
        parts = parts[:-1]
    # assign from end: state, city, village
    if parts:
        out['state'] = parts[-1]
        parts = parts[:-1]
    if parts:
        out['city'] = parts[-1]
        parts = parts[:-1]
    if parts:
        out['village'] = parts[-1]
        parts = parts[:-1]
    # remaining parts -> house_no / street / block
    if parts:
        out['house_no'] = parts[0]
        if len(parts) > 1:
            out['street'] = parts[1]
        if len(parts) > 2:
            out['block'] = parts[2]
    return out


@app.route('/')
def index():
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('index.html', products=products)


@app.route('/products')
def products():
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('products.html', products=products)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


# --- Cart routes ---


@app.route('/cart/add', methods=['POST'])
@login_required
def cart_add():
    product_id = request.form.get('product_id')
    qty = request.form.get('quantity', 1)
    try:
        qty = int(qty)
    except ValueError:
        qty = 1
    if not product_id:
        flash('Invalid product', 'danger')
        return redirect(request.referrer or url_for('products'))
    # ensure product exists
    p = Product.query.get(int(product_id))
    if not p:
        flash('Product not found', 'danger')
        return redirect(request.referrer or url_for('products'))

    # Persist cart item in DB for logged-in users
    ci = CartItem.query.filter_by(user_id=current_user.id, product_id=p.id).first()
    if ci:
        ci.quantity = (ci.quantity or 0) + qty
    else:
        ci = CartItem(user_id=current_user.id, product_id=p.id, quantity=qty)
        db.session.add(ci)
    db.session.commit()
    flash('Added to cart', 'success')
    return redirect(request.referrer or url_for('products'))


@app.route('/cart')
@login_required
def cart_view():
    items = []
    total = 0.0
    total_items = 0
    cis = CartItem.query.filter_by(user_id=current_user.id).all()
    for ci in cis:
        prod = ci.product
        if not prod:
            continue
        items.append({'product': prod, 'quantity': ci.quantity})
        qty = int(ci.quantity or 0)
        total_items += qty
        total += (prod.price or 0.0) * qty

    min_amount = app.config.get('MIN_ORDER_AMOUNT', 500)
    min_items = app.config.get('MIN_ORDER_MIN_ITEMS', 4)
    proceed_allowed = (total >= float(min_amount)) or (total_items >= int(min_items))

    return render_template('cart.html', items=items, total=total, total_items=total_items, min_amount=min_amount, min_items=min_items, proceed_allowed=proceed_allowed)


@app.route('/cart/update', methods=['POST'])
@login_required
def cart_update():
    # expects form fields 'qty_<product_id>' for updates
    cis = CartItem.query.filter_by(user_id=current_user.id).all()
    for ci in cis:
        field = f'qty_{ci.product_id}'
        if field in request.form:
            try:
                q = int(request.form.get(field, 0))
            except ValueError:
                q = 0
            if q <= 0:
                db.session.delete(ci)
            else:
                ci.quantity = q
    db.session.commit()
    flash('Cart updated', 'success')
    return redirect(url_for('cart_view'))


@app.route('/cart/address', methods=['GET', 'POST'])
@login_required
def cart_address():
    if request.method == 'POST':
        # collect address info
        name = request.form.get('name')
        phone = request.form.get('phone')
        address = request.form.get('address')
        house_no = request.form.get('house_no')
        street = request.form.get('street')
        block = request.form.get('block')
        village = request.form.get('village')
        city = request.form.get('city')
        state = request.form.get('state')
        zipcode = request.form.get('zipcode')

        # build full address if user filled components
        if not address:
            parts = [house_no, street, block, village, city, state, zipcode]
            address = ', '.join([p for p in parts if p])

        # If components are missing but a full address string exists, try to parse it
        if address:
            parsed = parse_address_string(address)
            # only fill components that were not provided explicitly
            if not house_no and parsed.get('house_no'):
                house_no = parsed.get('house_no')
            if not street and parsed.get('street'):
                street = parsed.get('street')
            if not block and parsed.get('block'):
                block = parsed.get('block')
            if not village and parsed.get('village'):
                village = parsed.get('village')
            if not city and parsed.get('city'):
                city = parsed.get('city')
            if not state and parsed.get('state'):
                state = parsed.get('state')
            if not zipcode and parsed.get('zipcode'):
                zipcode = parsed.get('zipcode')

        # simple validation
        if not address:
            flash('Please provide an address', 'warning')
            return redirect(url_for('cart_address'))

        # Enforce minimum order requirements before creating orders
        try:
            cis_check = CartItem.query.filter_by(user_id=current_user.id).all()
        except Exception:
            cis_check = []

        computed_total = 0.0
        computed_items = 0
        if cis_check:
            for ci in cis_check:
                prod = ci.product
                if not prod:
                    continue
                qty = int(ci.quantity or 0)
                computed_items += qty
                computed_total += (prod.price or 0.0) * qty
        else:
            session_cart = session.get('cart', {})
            for pid, qty in (session_cart or {}).items():
                try:
                    prod = Product.query.get(int(pid))
                except Exception:
                    prod = None
                if not prod:
                    continue
                qty_i = int(qty or 0)
                computed_items += qty_i
                computed_total += (prod.price or 0.0) * qty_i

        min_amount = app.config.get('MIN_ORDER_AMOUNT', 500)
        min_items = app.config.get('MIN_ORDER_MIN_ITEMS', 4)
        if not ((computed_total >= float(min_amount)) or (computed_items >= int(min_items))):
            flash(f'Minimum order requirement not met. Minimum ₹{min_amount} or at least {min_items} items required.', 'warning')
            return redirect(url_for('cart_view'))

        # Prefer DB-backed cart items for logged-in users
        cis = []
        try:
            cis = CartItem.query.filter_by(user_id=current_user.id).all()
        except Exception:
            cis = []

        # if DB cart empty, fallback to session cart
        if not cis:
            session_cart = session.get('cart', {})
            if not session_cart:
                flash('Cart is empty', 'warning')
                return redirect(url_for('products'))
            # create orders from session cart
            for pid, qty in session_cart.items():
                prod = Product.query.get(int(pid))
                if not prod:
                    continue
                order = Order(
                    user_id=current_user.id,
                    product=prod.name,
                    product_id=prod.id,
                    quantity=qty,
                    status='Pending',
                    name=name,
                    phone=phone,
                    address=address,
                    house_no=house_no,
                    street=street,
                    block=block,
                    village=village,
                    city=city,
                    state=state,
                    zipcode=zipcode
                )
                db.session.add(order)
            db.session.commit()
            session.pop('cart', None)
        else:
            # create orders from DB cart items
            for ci in cis:
                prod = ci.product
                if not prod:
                    continue
                order = Order(
                    user_id=current_user.id,
                    product=prod.name,
                    product_id=prod.id,
                    quantity=ci.quantity,
                    status='Pending',
                    name=name,
                    phone=phone,
                    address=address,
                    house_no=house_no,
                    street=street,
                    block=block,
                    village=village,
                    city=city,
                    state=state,
                    zipcode=zipcode
                )
                db.session.add(order)
            db.session.commit()
            # clear DB cart
            for ci in cis:
                db.session.delete(ci)
            db.session.commit()

        flash('Order placed. We will contact you for delivery details.', 'success')
        return redirect(url_for('my_orders'))

    return render_template('cart_address.html')


@app.route('/reverse_geocode', methods=['POST'])
@login_required
def reverse_geocode():
    data = request.get_json() or {}
    lat = data.get('lat')
    lon = data.get('lon')
    if lat is None or lon is None:
        return jsonify({'error': 'Missing coordinates'}), 400
    try:
        url = f'https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lon}'
        headers = {'User-Agent': 'VermaFashions/1.0'}
        r = requests.get(url, headers=headers, timeout=5)
        r.raise_for_status()
        data = r.json()
        address = data.get('display_name')
        return jsonify({'address': address})
    except Exception as e:
        return jsonify({'error': 'Reverse geocode failed'}), 500


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        user = User(name=name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        # generate and send verification OTP
        try:
            create_and_send_otp(email, purpose='verify', user_id=user.id)
            flash('Registration successful. A verification code was sent to your email. Check console if SMTP not configured.', 'success')
            return redirect(url_for('verify', email=email))
        except Exception as e:
            print(f"[Registration] OTP send error: {repr(e)}")
            flash('Registration created but failed to send verification code. Please contact admin or check server logs.', 'warning')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    prod = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=prod)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if not getattr(user, 'is_verified', False):
                flash('Please verify your email before logging in. A verification code was sent to your email.', 'warning')
                return redirect(url_for('verify', email=email))
            login_user(user)
            flash('Logged in successfully', 'success')
            next_page = request.args.get('next')
            # Redirect admins to admin area, others to products page
            if next_page:
                return redirect(next_page)
            if user.is_admin:
                # show admins the View All Products page by default
                return redirect(url_for('admin_view_products'))
            return redirect(url_for('products'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Separate admin login endpoint."""
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_view_products'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if not user.is_admin:
                flash('This account is not an admin account.', 'warning')
                return redirect(url_for('admin_login'))
            if not getattr(user, 'is_verified', False):
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('verify', email=email))
            login_user(user)
            flash('Admin logged in successfully', 'success')
            return redirect(url_for('admin_view_products'))
        flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html')


@app.route('/admin/setup', methods=['GET', 'POST'])
def admin_setup():
    """One-time admin account creation. Only available if no admin exists yet."""
    admin_exists = User.query.filter_by(is_admin=True).first() is not None
    if admin_exists:
        flash('An admin account already exists. Use /admin/login', 'info')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not name or not email or not password:
            flash('All fields are required', 'warning')
            return redirect(url_for('admin_setup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already in use', 'warning')
            return redirect(url_for('admin_setup'))
        
        # Create admin account (verified by default for setup convenience)
        admin = User(name=name, email=email, is_admin=True, is_verified=True)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        
        flash('Admin account created successfully. Please login.', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('admin_setup.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    email = request.args.get('email') or request.form.get('email')
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        email = request.form.get('email', '').strip()
        
        if not email or not code:
            flash('Provide email and code', 'warning')
            return redirect(url_for('verify', email=email))
        
        print(f"[Verify] Attempting verification for {email} with code {code}")
        
        otp = OTP.query.filter_by(email=email, purpose='verify', code=code, used=False).order_by(OTP.created_at.desc()).first()
        if not otp:
            print(f"[Verify] No matching OTP found for {email}/{code}")
            flash('Invalid verification code', 'danger')
            return redirect(url_for('verify', email=email))
        
        if otp.expires_at < datetime.utcnow():
            print(f"[Verify] OTP expired for {email}")
            flash('Code has expired. Request a new code.', 'warning')
            return redirect(url_for('resend_otp', email=email))
        
        otp.used = True
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            print(f"[Verify] Marked {email} as verified")
        db.session.commit()
        flash('Email verified. You may now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('verify.html', email=email)


@app.route('/resend-otp')
def resend_otp():
    email = request.args.get('email', '').strip()
    if not email:
        flash('Email missing', 'warning')
        return redirect(url_for('index'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('No user with that email', 'warning')
        return redirect(url_for('register'))
    if user.is_verified:
        flash('Account already verified. Please login.', 'info')
        return redirect(url_for('login'))
    try:
        create_and_send_otp(email, purpose='verify', user_id=user.id)
        flash('Verification code resent. Check console if SMTP not configured.', 'success')
    except Exception as e:
        print(f"[Resend OTP] Error: {repr(e)}")
        flash('Failed to send code. Check server logs.', 'danger')
    return redirect(url_for('verify', email=email))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Please provide an email address', 'warning')
            return redirect(url_for('forgot_password'))
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with that email', 'warning')
            return redirect(url_for('forgot_password'))
        try:
            print(f"[Forgot Password] Attempting to send reset OTP to {email}")
            create_and_send_otp(email, purpose='reset', user_id=user.id)
            print(f"[Forgot Password] OTP send completed for {email}")
            flash('A password reset code was sent to your email. Check your inbox and spam folder. If SMTP is not configured, check the server console.', 'success')
            return redirect(url_for('reset_password', email=email))
        except Exception as e:
            print(f"[Forgot Password] Error sending reset OTP to {email}: {str(e)}")
            flash(f'Error sending reset code. Check the server console for details.', 'danger')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email') or request.form.get('email')
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        code = request.form.get('code', '').strip()
        newpw = request.form.get('password', '').strip()
        if not email or not code or not newpw:
            flash('Please provide email, code and new password', 'warning')
            return redirect(url_for('reset_password', email=email))
        print(f"[Reset Password] Attempting password reset for {email}")
        otp = OTP.query.filter_by(email=email, purpose='reset', code=code, used=False).order_by(OTP.created_at.desc()).first()
        if not otp:
            print(f"[Reset Password] No valid OTP found for {email}/code={code}")
            flash('Invalid reset code', 'danger')
            return redirect(url_for('reset_password', email=email))
        if otp.expires_at < datetime.utcnow():
            print(f"[Reset Password] OTP expired for {email}")
            flash('Reset code expired', 'warning')
            return redirect(url_for('forgot_password'))
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"[Reset Password] User not found for {email}")
            flash('User not found', 'danger')
            return redirect(url_for('register'))
        user.set_password(newpw)
        otp.used = True
        db.session.commit()
        print(f"[Reset Password] Successfully reset password for {email}")
        flash('Password reset successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', email=email)


# If CSRF protection is enabled, exempt these auth/OTP endpoints (they accept simple form posts without Flask-WTF tokens)
# NOTE: This is done after all route definitions so the functions exist

@app.route('/order/new', methods=['GET', 'POST'])
@login_required
def new_order():
    # allow pre-filling the order form with a product (passed by product_id)
    product = None
    product_id = request.args.get('product_id')
    if product_id:
        try:
            product = Product.query.get(int(product_id))
        except Exception:
            product = None

    if request.method == 'POST':
        # product name may come from a hidden field when prefilled
        product_name = request.form.get('product')
        quantity = int(request.form.get('quantity', 1))
        order = Order(user_id=current_user.id, product=product_name, quantity=quantity)
        db.session.add(order)
        db.session.commit()
        flash('Order placed', 'success')
        return redirect(url_for('my_orders'))

    return render_template('new_order.html', product=product)


@app.route('/orders')
@login_required
def my_orders():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=orders)


@app.route('/order/<int:order_id>', methods=['GET', 'POST'])
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        content = request.form['content']
        msg = Message(order_id=order.id, sender=current_user.email, is_admin=current_user.is_admin, content=content)
        db.session.add(msg)
        db.session.commit()
        flash('Message sent', 'success')
        return redirect(url_for('order_detail', order_id=order.id))
    return render_template('order_detail.html', order=order)


@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    return redirect(url_for('admin_manage_products'))


@app.route('/admin/manage-products')
@login_required
def admin_manage_products():
    if not current_user.is_admin:
        abort(403)
    # Manage products page (upload only)
    return render_template('admin_manage_products.html')


@app.route('/admin/view-products')
@login_required
def admin_view_products():
    if not current_user.is_admin:
        abort(403)
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('admin_view_products.html', products=products)


@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        abort(403)
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('admin_orders.html', orders=orders)


@app.route('/admin/product/new', methods=['POST'])
@login_required
def admin_product_new():
    if not current_user.is_admin:
        abort(403)
    name = request.form.get('name')
    description = request.form.get('description')
    price_raw = request.form.get('price')
    quantity_raw = request.form.get('quantity')
    price = 0.0
    try:
        price = float(price_raw) if price_raw else 0.0
    except ValueError:
        price = 0.0
    try:
        quantity = int(quantity_raw) if quantity_raw else 0
    except ValueError:
        quantity = 0

    image = request.files.get('image')
    filename = None
    if image and allowed_file(image.filename):
        filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{image.filename}")
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(save_path)

    product = Product(name=name or 'Untitled', description=description, price=price, image_filename=filename, quantity=quantity)
    db.session.add(product)
    db.session.commit()
    flash('Product added', 'success')
    return redirect(url_for('admin_manage_products'))


@app.route('/admin/product/<int:product_id>/update-stock', methods=['POST'])
@login_required
def admin_update_product_stock(product_id):
    if not current_user.is_admin:
        abort(403)
    prod = Product.query.get_or_404(product_id)
    qty_raw = request.form.get('quantity')
    try:
        qty = int(qty_raw) if qty_raw is not None else prod.quantity
    except ValueError:
        qty = prod.quantity
    prod.quantity = max(0, qty)
    db.session.commit()
    flash(f'Stock for "{prod.name}" updated to {prod.quantity}', 'success')
    return redirect(request.referrer or url_for('admin_view_products'))


@app.route('/admin/product/<int:product_id>/delete', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    if not current_user.is_admin:
        abort(403)
    prod = Product.query.get_or_404(product_id)
    # attempt to remove image file
    try:
        if prod.image_filename:
            img_path = os.path.join(app.config['UPLOAD_FOLDER'], prod.image_filename)
            if os.path.exists(img_path):
                os.remove(img_path)
    except Exception:
        pass
    db.session.delete(prod)
    db.session.commit()
    flash(f'Product "{prod.name}" deleted', 'info')
    return redirect(request.referrer or url_for('admin_view_products'))


@app.route('/admin/order/<int:order_id>/packing')
@login_required
def admin_packing_slip(order_id):
    if not current_user.is_admin:
        abort(403)
    order = Order.query.get_or_404(order_id)
    return render_template('packing_slip.html', order=order)


@app.route('/admin/order/<int:order_id>/status', methods=['POST'])
@login_required
def update_status(order_id):
    if not current_user.is_admin:
        abort(403)
    order = Order.query.get_or_404(order_id)
    status = request.form.get('status')
    if status:
        order.status = status
        db.session.commit()
        flash('Status updated', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/order/<int:order_id>/accept', methods=['POST'])
@login_required
def admin_accept_order(order_id):
    if not current_user.is_admin:
        abort(403)
    order = Order.query.get_or_404(order_id)
    order.status = 'Accepted'
    # create an automatic message for the buyer
    try:
        msg = Message(order_id=order.id, sender=current_user.email, is_admin=True, content='Your order has been accepted and is being processed.')
        db.session.add(msg)
    except Exception:
        pass
    db.session.commit()
    flash(f'Order #{order.id} accepted', 'success')
    return redirect(request.referrer or url_for('admin_orders'))


@app.route('/admin/order/<int:order_id>/reject', methods=['POST'])
# Alias route for compatibility
@app.route('/admin/reject/<int:order_id>', methods=['POST'])
@login_required
def admin_reject_order(order_id):
    if not current_user.is_admin:
        abort(403)
    order = Order.query.get_or_404(order_id)
    # accept an optional reason from form
    reason = request.form.get('reason')
    order.status = 'Rejected'
    if reason:
        order.reject_reason = reason
    # create an automatic message for the buyer including reason
    try:
        content = 'Your order was rejected.'
        if reason:
            content = f"Your order was rejected: {reason}"
        msg = Message(order_id=order.id, sender=current_user.email, is_admin=True, content=content)
        db.session.add(msg)
    except Exception:
        pass
    db.session.commit()
    flash(f'Order #{order.id} rejected', 'info')
    return redirect(request.referrer or url_for('admin_orders'))


@app.route('/order/<int:order_id>/cancel', methods=['POST'])
@login_required
def user_cancel_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    # Only allow cancel when not accepted by admin
    if order.status == 'Accepted':
        flash('Order cannot be cancelled after acceptance', 'warning')
        return redirect(request.referrer or url_for('order_detail', order_id=order.id))
    order.status = 'Cancelled'
    db.session.commit()
    flash(f'Order #{order.id} cancelled', 'success')
    return redirect(url_for('my_orders'))


@app.route('/admin/order/<int:order_id>/message', methods=['POST'])
@login_required
def admin_message(order_id):
    if not current_user.is_admin:
        abort(403)
    order = Order.query.get_or_404(order_id)
    content = request.form.get('content')
    if content:
        msg = Message(order_id=order.id, sender=current_user.email, is_admin=True, content=content)
        db.session.add(msg)
        db.session.commit()
        flash('Message sent to buyer', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/order/<int:order_id>/delete', methods=['POST'])
@login_required
def admin_delete_order(order_id):
    if not current_user.is_admin:
        abort(403)
    order = Order.query.get_or_404(order_id)
    # Only allow deletion after rejection to avoid accidental deletes
    if order.status != 'Rejected':
        flash('Only rejected orders can be deleted', 'warning')
        return redirect(request.referrer or url_for('admin_orders'))
    try:
        # delete related messages first
        for m in list(order.messages):
            db.session.delete(m)
        db.session.delete(order)
        db.session.commit()
        flash(f'Order #{order_id} and related messages deleted', 'info')
    except Exception:
        db.session.rollback()
        flash('Failed to delete order', 'danger')
    return redirect(request.referrer or url_for('admin_orders'))


# Apply CSRF exemptions (after all routes are defined)
# Exempt all POST routes to avoid bad request errors on form submissions
# For production, implement proper CSRF tokens in all templates
try:
    if csrf:
        csrf.exempt(register)
        csrf.exempt(login)
        csrf.exempt(verify)
        csrf.exempt(resend_otp)
        csrf.exempt(forgot_password)
        csrf.exempt(reset_password)
        csrf.exempt(admin_login)
        csrf.exempt(admin_setup)
        csrf.exempt(cart_add)
        csrf.exempt(cart_update)
        csrf.exempt(cart_address)
        csrf.exempt(new_order)
        csrf.exempt(order_detail)
        csrf.exempt(admin_product_new)
        csrf.exempt(admin_update_product_stock)
        csrf.exempt(admin_delete_product)
        csrf.exempt(admin_manage_products)
        csrf.exempt(admin_accept_order)
        csrf.exempt(admin_reject_order)
        csrf.exempt(admin_delete_order)
        csrf.exempt(admin_message)
        csrf.exempt(user_cancel_order)
        csrf.exempt(update_status)
except Exception:
    pass


if __name__ == '__main__':
    create_tables()
    # Allow running on the local network by binding to 0.0.0.0 by default.
    host = os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
    try:
        port = int(os.environ.get('PORT', '5000'))
    except Exception:
        port = 5000
    debug = os.environ.get('FLASK_DEBUG', '1') in ('1', 'true', 'True')
    # Try to determine the machine's LAN IP for convenience printing (best-effort)
    local_ip = '127.0.0.1'
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't need to be reachable - used to pick a default outbound interface
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    print(f" * Starting Flask on {host}:{port} (open from other devices at http://{local_ip}:{port}/)")
    app.run(host=host, port=port, debug=debug)
