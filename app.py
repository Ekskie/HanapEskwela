from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'replace-with-a-secure-random-key'  # change for production

# --- Stub user store ---
# NOTE: passwords are hashed here for safety (even though it's in-memory).
USERS = {
    'admin@gmail.com': {
        'password': generate_password_hash('1234'),
        'is_admin': True,
        'name': 'Admin User'
    },
    'student1@example.com': {
        'password': generate_password_hash('student1'),
        'is_admin': False,
        'name': 'Student One'
    },
}

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user'):
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user'):
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('You do not have permission to access the admin area.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# --- Routes ---

# Root -> redirect to login
@app.route('/')
def root():
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to appropriate page
    if session.get('user'):
        if session.get('is_admin'):
            return redirect(url_for('admin_interface'))
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = USERS.get(email)
        if user and check_password_hash(user['password'], password):
            session['user'] = email
            session['name'] = user.get('name', email)
            session['is_admin'] = bool(user.get('is_admin'))
            flash('Logged in successfully.', 'success')
            if session['is_admin']:
                return redirect(url_for('admin_interface'))
            return redirect(url_for('index'))
        else:
            error = 'Invalid email or password.'

    return render_template('login.html', error=error)

# Public register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If already logged in, go to index
    if session.get('user'):
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or not password:
            error = 'All fields are required.'
        elif email in USERS:
            error = 'This email is already registered.'
        else:
            USERS[email] = {
                'password': generate_password_hash(password),
                'is_admin': False,
                'name': name
            }
            session['user'] = email
            session['name'] = name
            session['is_admin'] = False
            flash('Account created. You are now logged in.', 'success')
            return redirect(url_for('index'))

    return render_template('register.html', error=error)

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Authenticated index (schools listing placeholder)
@app.route('/index')
@login_required
def index():
    return render_template('index.html')

# Admin dashboard
@app.route('/admin')
@admin_required
def admin_interface():
    # Pass users (for display) - create a safe viewable list
    users_list = [
        {'email': email, 'name': info.get('name', ''), 'is_admin': bool(info.get('is_admin'))}
        for email, info in USERS.items()
    ]
    return render_template('admin_interface.html', users=users_list)

# Admin-only: create a new user (no public signup required)
@app.route('/admin/create_user', methods=['POST'])
@admin_required
def admin_create_user():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    is_admin = bool(request.form.get('is_admin'))

    if not name or not email or not password:
        flash('All fields are required to create a user.', 'error')
        return redirect(url_for('admin_interface'))

    if email in USERS:
        flash('This email is already registered.', 'error')
        return redirect(url_for('admin_interface'))

    USERS[email] = {
        'password': generate_password_hash(password),
        'is_admin': is_admin,
        'name': name
    }
    flash(f'User {name} <{email}> created.', 'success')
    return redirect(url_for('admin_interface'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
