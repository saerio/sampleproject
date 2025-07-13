from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import csv
import os
from datetime import datetime
import json
from functools import wraps
import hashlib

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this in production

# In-memory storage (use database in production)
users = {}
hall_passes = {}
audit_log = []

def log_audit_event(action, username, details, performed_by):
    """Add an entry to the audit log"""
    audit_log.append({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'action': action,
        'username': username,
        'details': details,
        'performed_by': performed_by
    })

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users_from_csv(filename):
    """Load users from CSV file"""
    global users
    users = {}
    try:
        with open(filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                username = row['username'].strip()
                role = row['role'].strip().lower()
                password = row['password'].strip()
                users[username] = {
                    'role': role,
                    'password_hash': hash_password(password)
                }
                
                # Initialize hall pass status for students
                if role == 'student':
                    hall_passes[username] = {
                        'active': False,
                        'issued_at': None,
                        'issued_by': None,
                        'destination': None,
                        'purpose': None
                    }
    except FileNotFoundError:
        print(f"CSV file {filename} not found. Please create it with columns: username,role,password")
    except Exception as e:
        print(f"Error loading CSV: {e}")

def require_login(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_role(allowed_roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            
            user_role = users.get(session['username'], {}).get('role')
            if user_role not in allowed_roles:
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            password_hash = hash_password(password)
            if users[username]['password_hash'] == password_hash:
                session['username'] = username
                session['role'] = users[username]['role']
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password', 'error')
        else:
            flash('Invalid username', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/audit')
@require_role(['admin'])
def audit():
    """View audit log (admin only)"""
    return render_template('audit.html', audit_log=audit_log)

@app.route('/log_unexcused/<username>', methods=['POST'])
@require_role(['admin', 'teacher'])
def log_unexcused(username):
    """Log an unexcused hall trip"""
    if username not in users or users[username]['role'] != 'student':
        return jsonify({'error': 'Student not found'}), 404
    
    location = request.form.get('location', 'Unknown location')
    notes = request.form.get('notes', '')
    
    details = f"Unexcused hall trip - Location: {location}"
    if notes:
        details += f", Notes: {notes}"
    
    log_audit_event('UNEXCUSED_TRIP', username, details, session['username'])
    flash(f'Unexcused trip logged for {username}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@require_login
def dashboard():
    user_role = session.get('role')
    
    if user_role in ['admin', 'teacher']:
        # Show all students and their hall pass status
        students = {username: data for username, data in users.items() if data['role'] == 'student'}
        return render_template('dashboard.html', students=students, hall_passes=hall_passes, user_role=user_role)
    else:
        # Regular users just see basic info
        return render_template('dashboard.html', user_role=user_role)

@app.route('/student/<username>')
def student_status(username):
    """Public page showing student's hall pass status"""
    if username not in users or users[username]['role'] != 'student':
        return "Student not found", 404
    
    status = hall_passes.get(username, {
        'active': False,
        'issued_at': None,
        'issued_by': None,
        'destination': None,
        'purpose': None
    })
    
    return render_template('student_status.html', username=username, status=status)

@app.route('/issue_pass/<username>', methods=['POST'])
@require_role(['admin', 'teacher'])
def issue_pass(username):
    """Issue a hall pass to a student"""
    if username not in users or users[username]['role'] != 'student':
        return jsonify({'error': 'Student not found'}), 404
    
    destination = request.form.get('destination', '')
    purpose = request.form.get('purpose', '')
    
    hall_passes[username] = {
        'active': True,
        'issued_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'issued_by': session['username'],
        'destination': destination,
        'purpose': purpose
    }
    
    # Log the action
    details = f"Pass issued - Destination: {destination}, Purpose: {purpose}"
    log_audit_event('PASS_ISSUED', username, details, session['username'])
    
    flash(f'Hall pass issued to {username}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/revoke_pass/<username>', methods=['POST'])
@require_role(['admin', 'teacher'])
def revoke_pass(username):
    """Revoke a student's hall pass"""
    if username not in users or users[username]['role'] != 'student':
        return jsonify({'error': 'Student not found'}), 404
    
    # Log the revocation before clearing
    old_pass = hall_passes.get(username, {})
    if old_pass.get('active'):
        details = f"Pass revoked - Was for: {old_pass.get('destination', 'Unknown')}"
        log_audit_event('PASS_REVOKED', username, details, session['username'])
    
    hall_passes[username] = {
        'active': False,
        'issued_at': None,
        'issued_by': None,
        'destination': None,
        'purpose': None
    }
    
    flash(f'Hall pass revoked for {username}', 'success')
    return redirect(url_for('dashboard'))

# Initialize the app
if __name__ == '__main__':
    # Load users from CSV on startup
    load_users_from_csv('users.csv')
    
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create basic HTML templates
    login_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Hall Pass Manager - Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; border-radius: 4px; width: 100%; }
        button:hover { background: #0056b3; }
        .error { color: red; margin: 10px 0; padding: 10px; background: #ffebee; border-radius: 4px; }
        .login-form { background: #f8f9fa; padding: 20px; border-radius: 8px; border: 1px solid #dee2e6; }
    </style>
</head>
<body>
    <div class="login-form">
        <h2>Hall Pass Manager Login</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="error">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''
    
    dashboard_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Hall Pass Manager - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .logout-btn { background: #dc3545; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; }
        .logout-btn:hover { background: #c82333; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .active { color: green; font-weight: bold; }
        .inactive { color: red; }
        .btn { padding: 6px 12px; margin: 2px; text-decoration: none; border: none; cursor: pointer; border-radius: 4px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-warning { background: #ffc107; color: #212529; }
        .btn:hover { opacity: 0.8; }
        .success { color: green; margin: 10px 0; }
        .error { color: red; margin: 10px 0; }
        .destination-input { width: 150px; }
    </style>
</head>
<body>
    <div class="header">
        <h2>Hall Pass Manager Dashboard</h2>
        <div>
            <span>Welcome, {{ session.username }} ({{ session.role }})</span>
            <a href="{{ url_for('logout') }}" class="logout-btn">Logout</a>
        </div>
    </div>
    
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    
    {% if user_role in ['admin', 'teacher'] %}
        <div style="margin: 20px 0;">
            {% if user_role == 'admin' %}
                <a href="{{ url_for('audit') }}" class="btn btn-primary">View Audit Log</a>
            {% endif %}
        </div>
        
        <h3>Student Hall Pass Status</h3>
        <table>
            <thead>
                <tr>
                    <th>Student</th>
                    <th>Status</th>
                    <th>Purpose</th>
                    <th>Issued By</th>
                    <th>Issued At</th>
                    <th>Actions</th>
                    {% if user_role == 'admin' %}
                        <th>Student Page</th>
                    {% endif %}
                </tr>
            </thead>
            <tbody>
                {% for username, user_data in students.items() %}
                    {% set status = hall_passes.get(username, {'active': False, 'issued_at': None, 'issued_by': None, 'destination': None, 'purpose': None}) %}
                    <tr>
                        <td>{{ username }}</td>
                        <td>
                            {% if status.active %}
                                <span class="active">Active</span>
                            {% else %}
                                <span class="inactive">Inactive</span>
                            {% endif %}
                        </td>
                        <td>{{ status.destination or '-' }}</td>
                        <td>{{ status.purpose or '-' }}</td>
                        <td>{{ status.issued_by or '-' }}</td>
                        <td>{{ status.issued_at or '-' }}</td>
                        <td>
                            {% if status.active %}
                                <form method="POST" action="{{ url_for('revoke_pass', username=username) }}" style="display: inline;">
                                    <button type="submit" class="btn btn-danger">Revoke</button>
                                </form>
                            {% else %}
                                <form method="POST" action="{{ url_for('issue_pass', username=username) }}" style="display: inline;">
                                    <input type="text" name="destination" placeholder="Destination" class="destination-input" required>
                                    <input type="text" name="purpose" placeholder="Purpose" class="destination-input" required>
                                    <button type="submit" class="btn btn-primary">Issue Pass</button>
                                </form>
                            {% endif %}
                            <br><br>
                            <form method="POST" action="{{ url_for('log_unexcused', username=username) }}" style="display: inline;">
                                <input type="text" name="location" placeholder="Location seen" class="destination-input" required>
                                <input type="text" name="notes" placeholder="Notes" class="destination-input">
                                <button type="submit" class="btn btn-warning">Log Unexcused</button>
                            </form>
                        </td>
                        {% if user_role == 'admin' %}
                            <td>
                                <a href="{{ url_for('student_status', username=username) }}" target="_blank" class="btn btn-primary">View Page</a>
                            </td>
                        {% endif %}
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p>Welcome to the Hall Pass Manager. Contact an administrator or teacher for hall pass requests.</p>
    {% endif %}
</body>
</html>
'''
    
    student_status_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Hall Pass Status - {{ username }}</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .status-card { border: 3px solid #ddd; padding: 30px; border-radius: 10px; margin: 20px 0; }
        .active { border-color: #28a745; background-color: #f8fff9; }
        .inactive { border-color: #dc3545; background-color: #fff8f8; }
        .status-text { font-size: 24px; font-weight: bold; margin: 10px 0; }
        .active .status-text { color: #28a745; }
        .inactive .status-text { color: #dc3545; }
        .details { margin: 15px 0; font-size: 16px; text-align: left; }
        .detail-item { margin: 8px 0; padding: 8px; background: #f8f9fa; border-radius: 4px; }
        .detail-label { font-weight: bold; color: #495057; }
        .refresh-btn { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 20px 0; display: inline-block; }
        .refresh-btn:hover { background: #0056b3; }
    </style>
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</head>
<body>
    <h1>Hall Pass Status</h1>
    <h2>{{ username }}</h2>
    
    <div class="status-card {% if status.active %}active{% else %}inactive{% endif %}">
        <div class="status-text">
            {% if status.active %}
                ✓ ACTIVE HALL PASS
            {% else %}
                ✗ NO ACTIVE HALL PASS
            {% endif %}
        </div>
        
        {% if status.active %}
            <div class="details">
                <div class="detail-item">
                    <span class="detail-label">Issued to:</span> {{ username }}
                </div>
                <div class="detail-item">
                    <span class="detail-label">Destination:</span> {{ status.destination or 'Not specified' }}
                </div>
                <div class="detail-item">
                    <span class="detail-label">Purpose:</span> {{ status.purpose or 'Not specified' }}
                </div>
                <div class="detail-item">
                    <span class="detail-label">Issued by:</span> {{ status.issued_by }}
                </div>
                <div class="detail-item">
                    <span class="detail-label">Issued at:</span> {{ status.issued_at }}
                </div>
            </div>
        {% else %}
            <div class="details">
                <div class="detail-item">
                    <span class="detail-label">Student:</span> {{ username }}
                </div>
                <div class="detail-item">
                    <span class="detail-label">Status:</span> No active hall pass
                </div>
            </div>
        {% endif %}
    </div>
    
    <a href="javascript:location.reload()" class="refresh-btn">Refresh Status</a>
    
    <p><small>This page refreshes automatically every 30 seconds</small></p>
</body>
</html>
'''
    
    # Write templates to files
    with open('templates/login.html', 'w') as f:
        f.write(login_html)
    
    with open('templates/dashboard.html', 'w') as f:
        f.write(dashboard_html)
    
    with open('templates/student_status.html', 'w') as f:
        f.write(student_status_html)
    
    # Create audit log template
    audit_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Audit Log - Hall Pass Manager</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .back-btn { background: #6c757d; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; }
        .back-btn:hover { background: #5a6268; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 14px; }
        th { background-color: #f2f2f2; position: sticky; top: 0; }
        .audit-row { }
        .audit-row:nth-child(even) { background-color: #f9f9f9; }
        .action-issued { color: #28a745; }
        .action-revoked { color: #dc3545; }
        .action-unexcused { color: #ffc107; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h2>Audit Log</h2>
        <a href="{{ url_for('dashboard') }}" class="back-btn">Back to Dashboard</a>
    </div>
    
    <div class="warning">
        <strong>Notice:</strong> This audit log cannot be modified or deleted through the dashboard. All hall pass activities are permanently recorded.
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Student</th>
                <th>Details</th>
                <th>Performed By</th>
            </tr>
        </thead>
        <tbody>
            {% for entry in audit_log[::-1] %}
                <tr class="audit-row">
                    <td>{{ entry.timestamp }}</td>
                    <td class="action-{{ entry.action.lower().replace('_', '-') }}">{{ entry.action.replace('_', ' ') }}</td>
                    <td>{{ entry.username }}</td>
                    <td>{{ entry.details }}</td>
                    <td>{{ entry.performed_by }}</td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
    
    {% if not audit_log %}
        <p>No audit entries found.</p>
    {% endif %}
</body>
</html>
'''
    
    with open('templates/audit.html', 'w') as f:
        f.write(audit_html)
    
    # Create sample CSV file if it doesn't exist
    if not os.path.exists('users.csv'):
        with open('users.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['username', 'role', 'password'])
            writer.writerow(['admin', 'admin', 'admin123'])
            writer.writerow(['teacher1', 'teacher', 'teacher123'])
            writer.writerow(['student1', 'student', 'student123'])
            writer.writerow(['student2', 'student', 'student123'])
        print("Created sample users.csv file")
    
    print("Hall Pass Manager starting...")
    print("Create a users.csv file with columns: username,role,password")
    print("Roles: admin, teacher, student")
    print("Students can be viewed at: /student/username")
    print("\nSample accounts:")
    print("admin/admin123, teacher1/teacher123, student1/student123")
    
    app.run(debug=True, host='0.0.0.0', port=5000)