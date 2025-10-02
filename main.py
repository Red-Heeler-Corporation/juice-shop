#!/usr/bin/env python3
"""
Vulnerable Payment Processing Application
Designed to test SAST scanners with sophisticated evasion techniques
"""

import os
import json
import time
import base64
import hashlib
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, send_file, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'vulnerable-secret-key-for-testing'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///payment_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORTS_DIR'] = 'reports'

# Initialize database
db = SQLAlchemy(app)

# Global variables for configuration
QUERY_CONFIGS = {
    'user_search': {'table': 'users', 'base': 'SELECT * FROM users WHERE '},
    'transaction_search': {'table': 'transactions', 'base': 'SELECT * FROM transactions WHERE '},
    'card_search': {'table': 'payment_cards', 'base': 'SELECT * FROM payment_cards WHERE '}
}

# Create upload and reports directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_DIR'], exist_ok=True)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')  # user, admin, merchant
    is_admin = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    kyc_verified = db.Column(db.Boolean, default=False)
    
    # Relationships
    cards = db.relationship('PaymentCard', backref='user', lazy=True)
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    refunds = db.relationship('Refund', backref='user', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_admin': self.is_admin,
            'balance': self.balance,
            'kyc_verified': self.kyc_verified
        }

class PaymentCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    card_number_encrypted = db.Column(db.String(255), nullable=False)
    cvv_hash = db.Column(db.String(255), nullable=False)
    expiry = db.Column(db.String(7), nullable=False)  # MM/YYYY
    cardholder_name = db.Column(db.String(100), nullable=False)
    billing_address = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'card_number': self.card_number_encrypted[-4:],  # Show last 4 digits
            'expiry': self.expiry,
            'cardholder_name': self.cardholder_name,
            'is_active': self.is_active
        }

class Merchant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    api_key = db.Column(db.String(255), unique=True, nullable=False)
    commission_rate = db.Column(db.Float, default=0.03)  # 3% commission
    settlement_balance = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    transactions = db.relationship('Transaction', backref='merchant', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'commission_rate': self.commission_rate,
            'settlement_balance': self.settlement_balance,
            'is_active': self.is_active
        }

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    merchant_id = db.Column(db.Integer, db.ForeignKey('merchant.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='USD')
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed, refunded
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    metadata = db.Column(db.Text)  # JSON string for additional data
    
    # Relationships
    refunds = db.relationship('Refund', backref='transaction', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'currency': self.currency,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'metadata': json.loads(self.metadata) if self.metadata else {}
        }

class Refund(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey('transaction.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'reason': self.reason,
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)  # JSON string for additional details
    
    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
            'details': json.loads(self.details) if self.details else {}
        }

class DiscountCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    percentage = db.Column(db.Float, nullable=False)  # 0.1 = 10% discount
    max_uses = db.Column(db.Integer, default=100)
    used_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'percentage': self.percentage,
            'max_uses': self.max_uses,
            'used_count': self.used_count,
            'is_active': self.is_active,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

# Helper Functions and Decorators
def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to check if user is admin - VULNERABLE: Only checks session, not database"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        # VULNERABILITY: Only checks session flag, not database
        if not session.get('is_admin', False):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def log_audit(user_id, action, resource_type, resource_id=None, details=None):
    """Log user actions for audit trail"""
    try:
        audit = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=request.remote_addr,
            details=json.dumps(details) if details else None
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        print(f"Audit logging failed: {e}")

def build_search_query(search_type, field, operator, value):
    """Build dynamic SQL queries - VULNERABLE to SQL injection"""
    if search_type not in QUERY_CONFIGS:
        return None
    
    base = QUERY_CONFIGS[search_type]['base']
    # VULNERABILITY: Direct string formatting without sanitization
    condition = f"{field} {operator} '{value}'"
    return base + condition

def execute_raw_query(query):
    """Execute raw SQL query - VULNERABLE"""
    try:
        conn = sqlite3.connect('payment_app.db')
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        return f"Query error: {str(e)}"

def safe_join_path(base, *paths):
    """Path joining function - VULNERABLE to path traversal"""
    # VULNERABILITY: Only filters ../ once, can be bypassed with ....//
    for path in paths:
        if '../' in path:
            path = path.replace('../', '')
        base = os.path.join(base, path)
    return base

def sanitize_html(text):
    """HTML sanitization - VULNERABLE: Only removes <script> tags"""
    # VULNERABILITY: Incomplete sanitization
    if text:
        text = text.replace('<script>', '').replace('</script>', '')
        text = text.replace('<SCRIPT>', '').replace('</SCRIPT>', '')
    return text

def encrypt_card_number(card_number):
    """Simple card number encryption - VULNERABLE"""
    # VULNERABILITY: Weak encryption
    return base64.b64encode(card_number.encode()).decode()

def decrypt_card_number(encrypted):
    """Simple card number decryption - VULNERABLE"""
    try:
        return base64.b64decode(encrypted.encode()).decode()
    except Exception:
        return "Invalid"

def hash_cvv(cvv):
    """Hash CVV - VULNERABLE: Weak hashing"""
    # VULNERABILITY: MD5 is cryptographically broken
    return hashlib.md5(cvv.encode()).hexdigest()

def validate_amount(amount):
    """Validate transaction amount - VULNERABLE: Allows negative amounts"""
    try:
        amount = float(amount)
        # VULNERABILITY: No validation for negative amounts
        return amount
    except Exception:
        return None

def apply_discount_code(code, amount):
    """Apply discount code - VULNERABLE: Can be applied multiple times"""
    discount = DiscountCode.query.filter_by(code=code, is_active=True).first()
    if not discount:
        return amount, "Invalid discount code"
    
    # VULNERABILITY: No check if already applied to this transaction
    if discount.used_count >= discount.max_uses:
        return amount, "Discount code expired"
    
    discounted_amount = amount * (1 - discount.percentage)
    discount.used_count += 1
    db.session.commit()
    
    return discounted_amount, "Discount applied"

def check_user_balance(user_id, amount):
    """Check if user has sufficient balance - VULNERABLE: Race condition"""
    user = User.query.get(user_id)
    if not user:
        return False
    
    # VULNERABILITY: TOCTOU - check happens here but balance could change
    return user.balance >= amount

def process_payment_internal(user_id, amount, merchant_id):
    """Internal payment processing - VULNERABLE: Race condition"""
    user = User.query.get(user_id)
    if not user:
        return False, "User not found"
    
    # VULNERABILITY: Check and deduct not atomic
    if user.balance >= amount:
        time.sleep(0.1)  # Simulate processing delay - creates race condition
        user.balance -= amount
        db.session.commit()
        return True, "Payment processed"
    else:
        return False, "Insufficient balance"

def generate_report_filename(user_id, report_type, date):
    """Generate report filename - VULNERABLE to path traversal"""
    # VULNERABILITY: User controls filename components
    filename = f"report_{user_id}_{report_type}_{date}.pdf"
    return safe_join_path(app.config['REPORTS_DIR'], filename)

def get_user_from_session():
    """Get current user from session"""
    if 'user_id' not in session:
        return None
    return User.query.get(session['user_id'])

def is_admin_user(user_id):
    """Check if user is admin - VULNERABLE: Only checks database once"""
    user = User.query.get(user_id)
    return user and user.is_admin

def update_user_profile(user_id, update_data):
    """Update user profile - VULNERABLE to mass assignment"""
    user = User.query.get(user_id)
    if not user:
        return False, "User not found"
    
    # VULNERABILITY: Mass assignment - applies all fields from request
    for key, value in update_data.items():
        if hasattr(user, key):
            setattr(user, key, value)  # Can set is_admin=True, role='admin', etc.
    
    try:
        db.session.commit()
        return True, "Profile updated"
    except Exception as e:
        db.session.rollback()
        return False, str(e)

# Authentication Endpoints
@app.route('/register', methods=['POST'])
def register():
    """User registration - VULNERABLE to mass assignment"""
    data = request.get_json()
    
    # VULNERABILITY: Mass assignment - accepts any field including is_admin
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create user with potential mass assignment
    user_data = {
        'username': username,
        'email': email,
        'password_hash': generate_password_hash(password)
    }
    
    # VULNERABILITY: Apply additional fields from request
    for key, value in data.items():
        if key not in ['username', 'email', 'password'] and hasattr(User, key):
            user_data[key] = value  # Can set is_admin=True, role='admin', etc.
    
    user = User(**user_data)
    
    try:
        db.session.add(user)
        db.session.commit()
        log_audit(user.id, 'user_registered', 'user', user.id)
        return jsonify({'message': 'User registered successfully', 'user_id': user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    """User login - VULNERABLE: Weak session management"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password_hash, password):
        # VULNERABILITY: Session data can be manipulated
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin  # This can be manipulated client-side
        session['role'] = user.role
        
        log_audit(user.id, 'user_login', 'user', user.id)
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict()
        }), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """User logout"""
    user_id = session.get('user_id')
    log_audit(user_id, 'user_logout', 'user', user_id)
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/user/profile', methods=['GET'])
@login_required
def get_profile():
    """Get user profile"""
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict()), 200

@app.route('/api/user/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile - VULNERABLE to mass assignment"""
    user = get_user_from_session()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    success, message = update_user_profile(user.id, data)
    
    if success:
        log_audit(user.id, 'profile_updated', 'user', user.id, data)
        return jsonify({'message': message}), 200
    else:
        return jsonify({'error': message}), 400

# SQL Injection Vulnerabilities
@app.route('/api/search/users', methods=['GET'])
@login_required
def search_users():
    """Search users - VULNERABLE to SQL injection"""
    search_type = request.args.get('type', 'user_search')
    field = request.args.get('field', 'username')
    operator = request.args.get('operator', '=')
    value = request.args.get('value', '')
    
    if not value:
        return jsonify({'error': 'Search value required'}), 400
    
    # VULNERABILITY: Build query with user input
    query = build_search_query(search_type, field, operator, value)
    if not query:
        return jsonify({'error': 'Invalid search type'}), 400
    
    try:
        results = execute_raw_query(query)
        return jsonify({'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/search/transactions', methods=['GET'])
@login_required
def search_transactions():
    """Search transactions - VULNERABLE to SQL injection"""
    user_id = session.get('user_id')
    
    # Get search parameters
    filter_expression = request.args.get('filter', '')
    sort_by = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'DESC')
    
    # VULNERABILITY: Direct SQL construction with user input
    base_query = f"SELECT * FROM transactions WHERE user_id = {user_id}"
    
    if filter_expression:
        # VULNERABILITY: User can inject SQL in filter_expression
        base_query += f" AND {filter_expression}"
    
    base_query += f" ORDER BY {sort_by} {order}"
    
    try:
        results = execute_raw_query(base_query)
        return jsonify({'transactions': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/advanced', methods=['GET'])
@login_required
def advanced_report():
    """Advanced reporting - VULNERABLE to SQL injection"""
    report_type = request.args.get('report_type', 'transactions')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    group_by = request.args.get('group_by', 'user_id')
    having_clause = request.args.get('having', '')
    
    user_id = session.get('user_id')
    
    # VULNERABILITY: Complex SQL construction with user input
    query_parts = [
        f"SELECT {group_by}, COUNT(*) as count, SUM(amount) as total",
        f"FROM {report_type}",
        f"WHERE user_id = {user_id}"
    ]
    
    if date_from:
        query_parts.append(f"AND created_at >= '{date_from}'")
    if date_to:
        query_parts.append(f"AND created_at <= '{date_to}'")
    
    query_parts.append(f"GROUP BY {group_by}")
    
    if having_clause:
        # VULNERABILITY: User can inject SQL in having clause
        query_parts.append(f"HAVING {having_clause}")
    
    query = " ".join(query_parts)
    
    try:
        results = execute_raw_query(query)
        return jsonify({'report': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/query', methods=['POST'])
@admin_required
def admin_query():
    """Admin query interface - VULNERABLE to SQL injection"""
    data = request.get_json()
    query_type = data.get('type', 'select')
    table = data.get('table', 'users')
    conditions = data.get('conditions', [])
    limit = data.get('limit', 100)
    
    # VULNERABILITY: Build query from user input
    if query_type == 'select':
        query = f"SELECT * FROM {table}"
        
        if conditions:
            where_clause = " AND ".join([f"{c['field']} {c['operator']} '{c['value']}'" for c in conditions])
            query += f" WHERE {where_clause}"
        
        query += f" LIMIT {limit}"
    
    try:
        results = execute_raw_query(query)
        return jsonify({'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cards/search', methods=['GET'])
@login_required
def search_cards():
    """Search payment cards - VULNERABLE to SQL injection"""
    user_id = session.get('user_id')
    
    # Get search parameters
    search_field = request.args.get('field', 'cardholder_name')
    search_value = request.args.get('value', '')
    search_operator = request.args.get('operator', 'LIKE')
    
    if not search_value:
        return jsonify({'error': 'Search value required'}), 400
    
    # VULNERABILITY: Dynamic field selection and value insertion
    if search_operator == 'LIKE':
        search_value = f"%{search_value}%"
    
    query = f"""
    SELECT id, cardholder_name, expiry, is_active 
    FROM payment_cards 
    WHERE user_id = {user_id} 
    AND {search_field} {search_operator} '{search_value}'
    """
    
    try:
        results = execute_raw_query(query)
        return jsonify({'cards': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Path Traversal Vulnerabilities
@app.route('/api/reports/download', methods=['GET'])
@login_required
def download_report():
    """Download user report - VULNERABLE to path traversal"""
    user_id = session.get('user_id')
    report_type = request.args.get('type', 'transaction')
    date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    
    # VULNERABILITY: User controls path components
    filename = generate_report_filename(user_id, report_type, date)
    
    try:
        return send_file(filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'Report not found'}), 404

@app.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    """File upload - VULNERABLE to path traversal"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # VULNERABILITY: User controls filename and subdirectory
    subdirectory = request.form.get('subdirectory', '')
    filename = secure_filename(file.filename)
    
    # VULNERABILITY: Path traversal through subdirectory parameter
    upload_path = safe_join_path(app.config['UPLOAD_FOLDER'], subdirectory, filename)
    
    try:
        os.makedirs(os.path.dirname(upload_path), exist_ok=True)
        file.save(upload_path)
        return jsonify({'message': 'File uploaded successfully', 'path': upload_path}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download', methods=['GET'])
@login_required
def download_file():
    """Download file - VULNERABLE to path traversal"""
    # Get file parameters
    file_category = request.args.get('category', '')  # Could be "../../etc"
    filename = request.args.get('filename', '')  # Could be "passwd"
    file_extension = request.args.get('extension', 'txt')
    
    if not filename:
        return jsonify({'error': 'Filename required'}), 400
    
    # VULNERABILITY: User controls all path components
    file_path = safe_join_path(app.config['UPLOAD_FOLDER'], file_category, f"{filename}.{file_extension}")
    
    try:
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/templates/render', methods=['POST'])
@login_required
def render_template():
    """Render template - VULNERABLE to path traversal"""
    data = request.get_json()
    template_name = data.get('template', 'default')
    template_data = data.get('data', {})
    
    # VULNERABILITY: User controls template path
    template_path = safe_join_path('templates', template_name)
    
    try:
        with open(template_path, 'r') as f:
            template_content = f.read()
        
        # VULNERABILITY: Also vulnerable to XSS
        rendered = template_content.format(**template_data)
        return jsonify({'rendered': rendered}), 200
    except FileNotFoundError:
        return jsonify({'error': 'Template not found'}), 404

@app.route('/api/logs/view', methods=['GET'])
@admin_required
def view_logs():
    """View log files - VULNERABLE to path traversal"""
    log_type = request.args.get('type', 'application')
    log_date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    
    # VULNERABILITY: User controls log file path
    log_filename = f"{log_type}_{log_date}.log"
    log_path = safe_join_path('logs', log_filename)
    
    try:
        with open(log_path, 'r') as f:
            log_content = f.read()
        return jsonify({'logs': log_content}), 200
    except FileNotFoundError:
        return jsonify({'error': 'Log file not found'}), 404

@app.route('/api/backups/restore', methods=['POST'])
@admin_required
def restore_backup():
    """Restore from backup - VULNERABLE to path traversal"""
    data = request.get_json()
    backup_name = data.get('backup_name', '')
    restore_path = data.get('restore_path', 'data')
    
    if not backup_name:
        return jsonify({'error': 'Backup name required'}), 400
    
    # VULNERABILITY: User controls both source and destination paths
    backup_file = safe_join_path('backups', backup_name)
    destination = safe_join_path(restore_path, 'restored_data')
    
    try:
        # Simulate backup restoration
        with open(backup_file, 'r') as src:
            content = src.read()
        
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, 'w') as dst:
            dst.write(content)
        
        return jsonify({'message': 'Backup restored successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# XSS Vulnerabilities
@app.route('/dashboard/<user_id>')
@login_required
def dashboard(user_id):
    """User dashboard - VULNERABLE to XSS"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # VULNERABILITY: Username from DB might contain XSS payload
    welcome_msg = f"<div class='welcome'>Hello, {user.username}!</div>"
    
    # VULNERABILITY: Using render_template_string with |safe filter
    return render_template_string("""
    <html>
    <head><title>Payment Dashboard</title></head>
    <body>
        <h1>Payment Dashboard</h1>
        {{ message|safe }}
        <div class="user-info">
            <p>Email: {{ user.email }}</p>
            <p>Balance: ${{ user.balance }}</p>
        </div>
    </body>
    </html>
    """, message=welcome_msg, user=user)

@app.route('/api/notifications', methods=['POST'])
@login_required
def create_notification():
    """Create notification - VULNERABLE to XSS"""
    data = request.get_json()
    message = data.get('message', '')
    user_id = session.get('user_id')
    
    # VULNERABILITY: Store user input in database without sanitization
    notification = {
        'user_id': user_id,
        'message': message,  # Can contain XSS payload
        'timestamp': datetime.now().isoformat()
    }
    
    # Store in session for demonstration
    if 'notifications' not in session:
        session['notifications'] = []
    session['notifications'].append(notification)
    
    return jsonify({'message': 'Notification created'}), 200

@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    """Get notifications - VULNERABLE to XSS"""
    notifications = session.get('notifications', [])
    
    # VULNERABILITY: Return JSON that frontend will insert with .innerHTML
    return jsonify({'notifications': notifications}), 200

@app.route('/api/error', methods=['GET'])
def error_page():
    """Error page - VULNERABLE to XSS via headers"""
    error_type = request.args.get('type', 'general')
    user_agent = request.headers.get('User-Agent', '')
    referer = request.headers.get('Referer', '')
    
    # VULNERABILITY: Reflect headers in error message
    error_message = f"""
    <div class="error">
        <h2>Error: {error_type}</h2>
        <p>User Agent: {user_agent}</p>
        <p>Referer: {referer}</p>
    </div>
    """
    
    return render_template_string("""
    <html>
    <head><title>Error</title></head>
    <body>{{ error_message|safe }}</body>
    </html>
    """, error_message=error_message)

@app.route('/api/search/results', methods=['GET'])
@login_required
def search_results():
    """Search results - VULNERABLE to XSS"""
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'all')
    
    # VULNERABILITY: Reflect search query in results
    results_html = f"""
    <div class="search-results">
        <h3>Search results for: {query}</h3>
        <p>Search type: {search_type}</p>
        <div class="results">
            <!-- Results would go here -->
        </div>
    </div>
    """
    
    return render_template_string("""
    <html>
    <head><title>Search Results</title></head>
    <body>{{ results|safe }}</body>
    </html>
    """, results=results_html)

@app.route('/api/comments', methods=['POST'])
@login_required
def add_comment():
    """Add comment - VULNERABLE to XSS"""
    data = request.get_json()
    comment_text = data.get('comment', '')
    transaction_id = data.get('transaction_id')
    user_id = session.get('user_id')
    
    # VULNERABILITY: Store comment without sanitization
    comment = {
        'id': len(session.get('comments', [])) + 1,
        'user_id': user_id,
        'transaction_id': transaction_id,
        'comment': comment_text,  # Can contain XSS payload
        'timestamp': datetime.now().isoformat()
    }
    
    if 'comments' not in session:
        session['comments'] = []
    session['comments'].append(comment)
    
    return jsonify({'message': 'Comment added', 'comment': comment}), 200

@app.route('/api/comments', methods=['GET'])
@login_required
def get_comments():
    """Get comments - VULNERABLE to XSS"""
    transaction_id = request.args.get('transaction_id')
    comments = session.get('comments', [])
    
    if transaction_id:
        comments = [c for c in comments if c.get('transaction_id') == int(transaction_id)]
    
    # VULNERABILITY: Return comments that will be rendered with |safe
    return jsonify({'comments': comments}), 200

@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile_display():
    """Update profile display - VULNERABLE to XSS"""
    data = request.get_json()
    user = get_user_from_session()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # VULNERABILITY: Update profile fields that will be displayed
    display_name = data.get('display_name', user.username)
    bio = data.get('bio', '')
    
    # Store in session for demonstration
    session['display_name'] = display_name
    session['bio'] = bio
    
    # VULNERABILITY: Return profile HTML with user input
    profile_html = f"""
    <div class="profile">
        <h2>{display_name}</h2>
        <p class="bio">{bio}</p>
    </div>
    """
    
    return jsonify({
        'message': 'Profile updated',
        'profile_html': profile_html
    }), 200

@app.route('/api/feedback', methods=['POST'])
@login_required
def submit_feedback():
    """Submit feedback - VULNERABLE to XSS"""
    data = request.get_json()
    feedback_text = data.get('feedback', '')
    rating = data.get('rating', 5)
    user_id = session.get('user_id')
    
    # VULNERABILITY: Store feedback without sanitization
    feedback = {
        'id': len(session.get('feedback', [])) + 1,
        'user_id': user_id,
        'feedback': feedback_text,  # Can contain XSS payload
        'rating': rating,
        'timestamp': datetime.now().isoformat()
    }
    
    if 'feedback' not in session:
        session['feedback'] = []
    session['feedback'].append(feedback)
    
    # VULNERABILITY: Return feedback HTML
    feedback_html = f"""
    <div class="feedback-item">
        <p>Rating: {'★' * rating}</p>
        <p>Feedback: {feedback_text}</p>
    </div>
    """
    
    return jsonify({
        'message': 'Feedback submitted',
        'feedback_html': feedback_html
    }), 200

# Business Logic Flaws
@app.route('/api/payment/process', methods=['POST'])
@login_required
def process_payment():
    """Process payment - VULNERABLE to business logic flaws"""
    data = request.get_json()
    amount = data.get('amount', 0)
    merchant_id = data.get('merchant_id')
    user_id = session.get('user_id')
    
    # VULNERABILITY: No validation for negative amounts
    amount = validate_amount(amount)
    if amount is None:
        return jsonify({'error': 'Invalid amount'}), 400
    
    # VULNERABILITY: Allow negative amounts (add money by "spending" -$100)
    if amount < 0:
        # This is a business logic flaw - negative payments should add money
        user = User.query.get(user_id)
        user.balance += abs(amount)  # Add the absolute value
        db.session.commit()
        return jsonify({'message': f'Added ${abs(amount)} to balance'}), 200
    
    # VULNERABILITY: Race condition - check balance, then process
    if not check_user_balance(user_id, amount):
        return jsonify({'error': 'Insufficient balance'}), 400
    
    # VULNERABILITY: TOCTOU - balance could change between check and deduct
    success, message = process_payment_internal(user_id, amount, merchant_id)
    
    if success:
        # Create transaction record
        transaction = Transaction(
            user_id=user_id,
            merchant_id=merchant_id,
            amount=amount,
            status='completed'
        )
        db.session.add(transaction)
        db.session.commit()
        
        log_audit(user_id, 'payment_processed', 'transaction', transaction.id)
        return jsonify({'message': 'Payment processed successfully', 'transaction_id': transaction.id}), 200
    else:
        return jsonify({'error': message}), 400

@app.route('/api/discount/apply', methods=['POST'])
@login_required
def apply_discount():
    """Apply discount code - VULNERABLE to multiple applications"""
    data = request.get_json()
    code = data.get('code', '')
    amount = data.get('amount', 0)
    
    if not code:
        return jsonify({'error': 'Discount code required'}), 400
    
    # VULNERABILITY: Can apply same discount multiple times
    discounted_amount, message = apply_discount_code(code, amount)
    
    # Store in session for demonstration
    if 'applied_discounts' not in session:
        session['applied_discounts'] = []
    session['applied_discounts'].append({
        'code': code,
        'original_amount': amount,
        'discounted_amount': discounted_amount,
        'timestamp': datetime.now().isoformat()
    })
    
    return jsonify({
        'message': message,
        'original_amount': amount,
        'discounted_amount': discounted_amount
    }), 200

@app.route('/api/refund/create', methods=['POST'])
@login_required
def create_refund():
    """Create refund - VULNERABLE to business logic flaws"""
    data = request.get_json()
    transaction_id = data.get('transaction_id')
    amount = data.get('amount', 0)
    reason = data.get('reason', '')
    user_id = session.get('user_id')
    
    # VULNERABILITY: No verification that transaction belongs to user
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    # VULNERABILITY: No verification that transaction was successful
    if transaction.status != 'completed':
        return jsonify({'error': 'Transaction not completed'}), 400
    
    # VULNERABILITY: Allow refunding more than original amount
    if amount > transaction.amount:
        return jsonify({'error': 'Refund amount exceeds transaction amount'}), 400
    
    # VULNERABILITY: No check for existing refunds
    existing_refund = Refund.query.filter_by(transaction_id=transaction_id).first()
    if existing_refund:
        return jsonify({'error': 'Refund already exists'}), 400
    
    # Create refund
    refund = Refund(
        transaction_id=transaction_id,
        user_id=user_id,
        amount=amount,
        reason=reason,
        status='pending'
    )
    db.session.add(refund)
    db.session.commit()
    
    log_audit(user_id, 'refund_created', 'refund', refund.id)
    return jsonify({'message': 'Refund created', 'refund_id': refund.id}), 200

@app.route('/api/refund/<refund_id>/approve', methods=['POST'])
@admin_required
def approve_refund(refund_id):
    """Approve refund - VULNERABLE to business logic flaws"""
    refund = Refund.query.get(refund_id)
    if not refund:
        return jsonify({'error': 'Refund not found'}), 404
    
    # VULNERABILITY: No verification of refund amount vs transaction amount
    # VULNERABILITY: No check if user has sufficient balance for refund
    
    # Approve refund
    refund.status = 'approved'
    refund.approved_by = session.get('user_id')
    
    # VULNERABILITY: Add refund amount to user balance without verification
    user = User.query.get(refund.user_id)
    user.balance += refund.amount
    
    # VULNERABILITY: Update transaction status without proper validation
    transaction = Transaction.query.get(refund.transaction_id)
    transaction.status = 'refunded'
    
    db.session.commit()
    
    log_audit(session.get('user_id'), 'refund_approved', 'refund', refund.id)
    return jsonify({'message': 'Refund approved'}), 200

@app.route('/api/currency/convert', methods=['POST'])
@login_required
def convert_currency():
    """Currency conversion - VULNERABLE to rounding errors"""
    data = request.get_json()
    amount = data.get('amount', 0)
    from_currency = data.get('from_currency', 'USD')
    to_currency = data.get('to_currency', 'EUR')
    
    # VULNERABILITY: Simple conversion with rounding errors
    conversion_rates = {
        'USD': {'EUR': 0.85, 'GBP': 0.73, 'JPY': 110.0},
        'EUR': {'USD': 1.18, 'GBP': 0.86, 'JPY': 129.0},
        'GBP': {'USD': 1.37, 'EUR': 1.16, 'JPY': 150.0}
    }
    
    if from_currency not in conversion_rates or to_currency not in conversion_rates[from_currency]:
        return jsonify({'error': 'Unsupported currency'}), 400
    
    rate = conversion_rates[from_currency][to_currency]
    converted_amount = amount * rate
    
    # VULNERABILITY: Rounding errors accumulate over multiple conversions
    converted_amount = round(converted_amount, 2)
    
    return jsonify({
        'original_amount': amount,
        'from_currency': from_currency,
        'to_currency': to_currency,
        'converted_amount': converted_amount,
        'rate': rate
    }), 200

@app.route('/api/balance/withdraw', methods=['POST'])
@login_required
def withdraw_balance():
    """Withdraw balance - VULNERABLE to integer overflow"""
    data = request.get_json()
    amount = data.get('amount', 0)
    user_id = session.get('user_id')
    
    # VULNERABILITY: No validation for extremely large amounts
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # VULNERABILITY: Integer overflow in amount calculations
    if user.balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400
    
    # VULNERABILITY: No upper limit on withdrawal amount
    user.balance -= amount
    db.session.commit()
    
    log_audit(user_id, 'balance_withdrawn', 'user', user_id, {'amount': amount})
    return jsonify({'message': 'Withdrawal successful', 'new_balance': user.balance}), 200

# IDOR and BOLA Vulnerabilities
@app.route('/api/card/<card_id>', methods=['GET'])
@login_required
def get_card(card_id):
    """Get payment card - VULNERABLE to IDOR"""
    # VULNERABILITY: No ownership verification
    card = PaymentCard.query.get(card_id)
    if not card:
        return jsonify({'error': 'Card not found'}), 404
    
    return jsonify(card.to_dict()), 200

@app.route('/api/card/<card_id>', methods=['PUT'])
@login_required
def update_card(card_id):
    """Update payment card - VULNERABLE to IDOR"""
    data = request.get_json()
    
    # VULNERABILITY: No ownership verification
    card = PaymentCard.query.get(card_id)
    if not card:
        return jsonify({'error': 'Card not found'}), 404
    
    # VULNERABILITY: Allow updating any card
    card.cardholder_name = data.get('cardholder_name', card.cardholder_name)
    card.billing_address = data.get('billing_address', card.billing_address)
    card.is_active = data.get('is_active', card.is_active)
    
    db.session.commit()
    
    log_audit(session.get('user_id'), 'card_updated', 'payment_card', card_id)
    return jsonify({'message': 'Card updated successfully'}), 200

@app.route('/api/card/<card_id>', methods=['DELETE'])
@login_required
def delete_card(card_id):
    """Delete payment card - VULNERABLE to IDOR"""
    # VULNERABILITY: No ownership verification
    card = PaymentCard.query.get(card_id)
    if not card:
        return jsonify({'error': 'Card not found'}), 404
    
    db.session.delete(card)
    db.session.commit()
    
    log_audit(session.get('user_id'), 'card_deleted', 'payment_card', card_id)
    return jsonify({'message': 'Card deleted successfully'}), 200

@app.route('/api/transaction/<transaction_id>', methods=['GET'])
@login_required
def get_transaction(transaction_id):
    """Get transaction - VULNERABLE to IDOR"""
    # VULNERABILITY: No ownership verification
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    return jsonify(transaction.to_dict()), 200

@app.route('/api/transaction/<transaction_id>/refund', methods=['POST'])
@login_required
def refund_transaction(transaction_id):
    """Refund transaction - VULNERABLE to IDOR"""
    data = request.get_json()
    amount = data.get('amount', 0)
    reason = data.get('reason', '')
    user_id = session.get('user_id')
    
    # VULNERABILITY: Check existence but not ownership
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    # VULNERABILITY: No verification that transaction belongs to user
    if transaction.status != 'completed':
        return jsonify({'error': 'Transaction not completed'}), 400
    
    # Create refund for any transaction
    refund = Refund(
        transaction_id=transaction_id,
        user_id=user_id,  # This could be different from transaction.user_id
        amount=amount,
        reason=reason,
        status='pending'
    )
    db.session.add(refund)
    db.session.commit()
    
    log_audit(user_id, 'refund_created', 'refund', refund.id)
    return jsonify({'message': 'Refund created', 'refund_id': refund.id}), 200

@app.route('/api/user/<user_id>/cards', methods=['GET'])
@login_required
def get_user_cards(user_id):
    """Get user cards - VULNERABLE to BOLA"""
    # VULNERABILITY: No authorization check - can access any user's cards
    cards = PaymentCard.query.filter_by(user_id=user_id).all()
    
    return jsonify({'cards': [card.to_dict() for card in cards]}), 200

@app.route('/api/user/<user_id>/transactions', methods=['GET'])
@login_required
def get_user_transactions(user_id):
    """Get user transactions - VULNERABLE to BOLA"""
    # VULNERABILITY: No authorization check - can access any user's transactions
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    
    return jsonify({'transactions': [txn.to_dict() for txn in transactions]}), 200

@app.route('/api/user/<user_id>/balance', methods=['GET'])
@login_required
def get_user_balance(user_id):
    """Get user balance - VULNERABLE to BOLA"""
    # VULNERABILITY: No authorization check - can access any user's balance
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'balance': user.balance}), 200

@app.route('/api/user/<user_id>/profile', methods=['GET'])
@login_required
def get_user_profile(user_id):
    """Get user profile - VULNERABLE to BOLA"""
    # VULNERABILITY: No authorization check - can access any user's profile
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict()), 200

@app.route('/api/merchant/<merchant_id>/stats', methods=['GET'])
@login_required
def get_merchant_stats(merchant_id):
    """Get merchant stats - VULNERABLE to BOLA"""
    # VULNERABILITY: No authorization check - can access any merchant's stats
    merchant = Merchant.query.get(merchant_id)
    if not merchant:
        return jsonify({'error': 'Merchant not found'}), 404
    
    # Get transaction stats
    transactions = Transaction.query.filter_by(merchant_id=merchant_id).all()
    total_amount = sum(txn.amount for txn in transactions)
    
    stats = {
        'merchant_id': merchant_id,
        'total_transactions': len(transactions),
        'total_amount': total_amount,
        'settlement_balance': merchant.settlement_balance
    }
    
    return jsonify(stats), 200

@app.route('/api/refund/<refund_id>', methods=['GET'])
@login_required
def get_refund(refund_id):
    """Get refund - VULNERABLE to IDOR"""
    # VULNERABILITY: No ownership verification
    refund = Refund.query.get(refund_id)
    if not refund:
        return jsonify({'error': 'Refund not found'}), 404
    
    return jsonify(refund.to_dict()), 200

@app.route('/api/refund/<refund_id>', methods=['PUT'])
@login_required
def update_refund(refund_id):
    """Update refund - VULNERABLE to IDOR"""
    data = request.get_json()
    
    # VULNERABILITY: No ownership verification
    refund = Refund.query.get(refund_id)
    if not refund:
        return jsonify({'error': 'Refund not found'}), 404
    
    # VULNERABILITY: Allow updating any refund
    refund.amount = data.get('amount', refund.amount)
    refund.reason = data.get('reason', refund.reason)
    refund.status = data.get('status', refund.status)
    
    db.session.commit()
    
    log_audit(session.get('user_id'), 'refund_updated', 'refund', refund_id)
    return jsonify({'message': 'Refund updated successfully'}), 200

# Missing Authorization Vulnerabilities
@app.route('/api/admin/users', methods=['GET'])
@login_required  # VULNERABILITY: Only checks authentication, not admin role
def list_all_users():
    """List all users - VULNERABLE: Missing admin authorization"""
    users = User.query.all()
    return jsonify({'users': [user.to_dict() for user in users]}), 200

@app.route('/api/admin/transactions', methods=['GET'])
@login_required  # VULNERABILITY: Only checks authentication, not admin role
def list_all_transactions():
    """List all transactions - VULNERABLE: Missing admin authorization"""
    transactions = Transaction.query.all()
    return jsonify({'transactions': [txn.to_dict() for txn in transactions]}), 200

@app.route('/api/admin/audit-log', methods=['GET'])
@login_required  # VULNERABILITY: Only checks authentication, not admin role
def get_audit_log():
    """Get audit log - VULNERABLE: Missing admin authorization"""
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify({'audit_logs': [log.to_dict() for log in logs]}), 200

@app.route('/api/merchant/<merchant_id>/balance', methods=['GET'])
def get_merchant_balance(merchant_id):
    """Get merchant balance - VULNERABLE: No authentication at all"""
    # VULNERABILITY: Public endpoint for sensitive data
    merchant = Merchant.query.get(merchant_id)
    if not merchant:
        return jsonify({'error': 'Merchant not found'}), 404
    
    return jsonify({'balance': merchant.settlement_balance}), 200

@app.route('/api/merchant/<merchant_id>/settlement', methods=['POST'])
def process_settlement(merchant_id):
    """Process merchant settlement - VULNERABLE: No authentication"""
    # VULNERABILITY: Public endpoint for financial operations
    merchant = Merchant.query.get(merchant_id)
    if not merchant:
        return jsonify({'error': 'Merchant not found'}), 404
    
    # Process settlement
    settlement_amount = merchant.settlement_balance
    merchant.settlement_balance = 0.0
    db.session.commit()
    
    return jsonify({
        'message': 'Settlement processed',
        'amount': settlement_amount
    }), 200

@app.route('/api/internal/health', methods=['GET'])
def health_check():
    """Health check - VULNERABLE: Exposes sensitive information"""
    # VULNERABILITY: Internal endpoint without authentication
    db_status = "connected" if db.session.execute("SELECT 1").scalar() else "disconnected"
    
    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'users_count': User.query.count(),
        'transactions_count': Transaction.query.count()
    }), 200

@app.route('/api/debug/session', methods=['GET'])
def debug_session():
    """Debug session - VULNERABLE: Exposes session data"""
    # VULNERABILITY: Debug endpoint without authentication
    return jsonify({
        'session': dict(session),
        'headers': dict(request.headers),
        'remote_addr': request.remote_addr
    }), 200

@app.route('/api/debug/database', methods=['GET'])
def debug_database():
    """Debug database - VULNERABLE: Exposes database info"""
    # VULNERABILITY: Debug endpoint without authentication
    try:
        # Get table counts
        tables = {
            'users': User.query.count(),
            'transactions': Transaction.query.count(),
            'cards': PaymentCard.query.count(),
            'merchants': Merchant.query.count(),
            'refunds': Refund.query.count()
        }
        
        return jsonify({
            'status': 'connected',
            'tables': tables
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/version', methods=['GET'])
def get_version():
    """Get version info - VULNERABLE: Exposes system information"""
    # VULNERABILITY: Public endpoint exposing system details
    return jsonify({
        'version': '1.0.0',
        'environment': 'development',
        'database': 'sqlite',
        'python_version': '3.9',
        'flask_version': '2.0.0'
    }), 200

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get configuration - VULNERABLE: Exposes sensitive config"""
    # VULNERABILITY: Public endpoint exposing configuration
    return jsonify({
        'secret_key': app.config.get('SECRET_KEY'),
        'database_uri': app.config.get('SQLALCHEMY_DATABASE_URI'),
        'upload_folder': app.config.get('UPLOAD_FOLDER'),
        'reports_dir': app.config.get('REPORTS_DIR')
    }), 200

@app.route('/api/merchant-portal/<merchant_id>', methods=['GET'])
def merchant_portal(merchant_id):
    """Merchant portal - VULNERABLE: No authentication"""
    # VULNERABILITY: Public merchant portal
    merchant = Merchant.query.get(merchant_id)
    if not merchant:
        return jsonify({'error': 'Merchant not found'}), 404
    
    # Get merchant data
    transactions = Transaction.query.filter_by(merchant_id=merchant_id).all()
    total_amount = sum(txn.amount for txn in transactions)
    
    portal_data = {
        'merchant': merchant.to_dict(),
        'total_transactions': len(transactions),
        'total_amount': total_amount,
        'settlement_balance': merchant.settlement_balance
    }
    
    return jsonify(portal_data), 200

@app.route('/api/v2/users', methods=['GET'])
def list_users_v2():
    """List users v2 - VULNERABLE: Different version without auth"""
    # VULNERABILITY: API versioning where v1 is protected but v2 isn't
    users = User.query.all()
    return jsonify({'users': [user.to_dict() for user in users]}), 200

@app.route('/api/v2/transactions', methods=['GET'])
def list_transactions_v2():
    """List transactions v2 - VULNERABLE: Different version without auth"""
    # VULNERABILITY: API versioning where v1 is protected but v2 isn't
    transactions = Transaction.query.all()
    return jsonify({'transactions': [txn.to_dict() for txn in transactions]}), 200

# Additional Payment Card Endpoints
@app.route('/api/card/add', methods=['POST'])
@login_required
def add_card():
    """Add payment card - VULNERABLE to mass assignment"""
    data = request.get_json()
    user_id = session.get('user_id')
    
    # VULNERABILITY: Mass assignment - accepts any field
    card_data = {
        'user_id': user_id,
        'card_number_encrypted': encrypt_card_number(data.get('card_number', '')),
        'cvv_hash': hash_cvv(data.get('cvv', '')),
        'expiry': data.get('expiry', ''),
        'cardholder_name': data.get('cardholder_name', ''),
        'billing_address': data.get('billing_address', '')
    }
    
    # VULNERABILITY: Apply additional fields from request
    for key, value in data.items():
        if key not in ['card_number', 'cvv', 'expiry', 'cardholder_name', 'billing_address'] and hasattr(PaymentCard, key):
            card_data[key] = value  # Can set is_active=False, etc.
    
    card = PaymentCard(**card_data)
    
    try:
        db.session.add(card)
        db.session.commit()
        log_audit(user_id, 'card_added', 'payment_card', card.id)
        return jsonify({'message': 'Card added successfully', 'card_id': card.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Finalize Application
@app.route('/')
def index():
    """Home page"""
    return jsonify({
        'message': 'Vulnerable Payment Processing API',
        'version': '1.0.0',
        'endpoints': {
            'auth': ['/register', '/login', '/logout'],
            'user': ['/api/user/profile', '/api/user/update'],
            'cards': ['/api/card/add', '/api/card/<id>', '/api/card/<id>/delete'],
            'transactions': ['/api/transaction/create', '/api/transaction/<id>'],
            'admin': ['/api/admin/users', '/api/admin/transactions'],
            'search': ['/api/search/users', '/api/search/transactions'],
            'reports': ['/api/reports/download', '/api/reports/advanced']
        },
        'vulnerabilities': [
            'SQL Injection', 'Path Traversal', 'XSS', 'Business Logic Flaws',
            'IDOR/BOLA', 'Mass Assignment', 'Missing Authorization'
        ]
    }), 200

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

def init_db():
    """Initialize database with sample data"""
    db.create_all()
    
    # Create sample users
    if User.query.count() == 0:
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            is_admin=True,
            balance=10000.0,
            kyc_verified=True
        )
        
        regular_user = User(
            username='user1',
            email='user1@example.com',
            password_hash=generate_password_hash('user123'),
            role='user',
            is_admin=False,
            balance=1000.0,
            kyc_verified=True
        )
        
        merchant_user = User(
            username='merchant1',
            email='merchant1@example.com',
            password_hash=generate_password_hash('merchant123'),
            role='merchant',
            is_admin=False,
            balance=5000.0,
            kyc_verified=True
        )
        
        db.session.add(admin_user)
        db.session.add(regular_user)
        db.session.add(merchant_user)
        db.session.commit()
        
        # Create sample merchant
        merchant = Merchant(
            name='Test Merchant',
            api_key='test_api_key_123',
            commission_rate=0.03,
            settlement_balance=0.0
        )
        db.session.add(merchant)
        db.session.commit()
        
        # Create sample discount codes
        discount1 = DiscountCode(
            code='WELCOME10',
            percentage=0.10,
            max_uses=100,
            used_count=0
        )
        
        discount2 = DiscountCode(
            code='SAVE20',
            percentage=0.20,
            max_uses=50,
            used_count=0
        )
        
        db.session.add(discount1)
        db.session.add(discount2)
        db.session.commit()
        
        print("Database initialized with sample data")

if __name__ == '__main__':
    with app.app_context():
        init_db()
    
    print("Starting Vulnerable Payment Processing API...")
    print("Available endpoints:")
    print("- Authentication: /register, /login, /logout")
    print("- User management: /api/user/*")
    print("- Payment cards: /api/card/*")
    print("- Transactions: /api/transaction/*")
    print("- Admin functions: /api/admin/*")
    print("- Search functions: /api/search/*")
    print("- Reports: /api/reports/*")
    print("- Debug endpoints: /api/debug/*")
    print("\nVulnerabilities implemented:")
    print("- SQL Injection (multiple endpoints)")
    print("- Path Traversal (file operations)")
    print("- XSS (template rendering)")
    print("- Business Logic Flaws (payment processing)")
    print("- IDOR/BOLA (resource access)")
    print("- Mass Assignment (user/card creation)")
    print("- Missing Authorization (admin endpoints)")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
