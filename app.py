import os
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from supabase import create_client, Client

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-dev-key')

# --- SUPABASE CONFIGURATION ---
url = os.getenv('SUPABASE_URL')
key = os.getenv('SUPABASE_KEY')

if not url or not key:
    raise ValueError("Supabase URL and Key are missing. Please check your .env file.")

supabase: Client = create_client(url, key)

# --- SMTP / EMAIL FUNCTIONS ---

def send_2fa_email(to_email, code):
    """Sends a 2FA verification code via SMTP (Brevo)"""
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USERNAME')
    smtp_password = os.getenv('SMTP_PASSWORD')
    smtp_sender = os.getenv('SMTP_SENDER')

    if not all([smtp_server, smtp_user, smtp_password]):
        print("⚠️ SMTP credentials missing. 2FA code printed to console instead.")
        print(f"👉 2FA CODE FOR {to_email}: {code}")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_sender
        msg['To'] = to_email
        msg['Subject'] = "HanapEskwela Admin Verification Code"

        body = f"""
        <html>
          <body>
            <h2>Admin Login Verification</h2>
            <p>Your two-factor authentication code is:</p>
            <h1 style="color: #2E7D32; letter-spacing: 5px;">{code}</h1>
            <p>If you did not request this, please ignore this email.</p>
          </body>
        </html>
        """
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        return False

# --- Helper Functions ---

def get_public_profile(user_id):
    """Fetch public user profile (admin status, ban status)"""
    try:
        response = supabase.table('users').select("*").eq('id', user_id).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        print(f"Error fetching profile: {e}")
        return None

# --- Decorators ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        
        # Check ban status from public profile
        profile = get_public_profile(session.get('user_id'))
        if not profile or not profile.get('is_active', True):
            session.clear()
            flash('Your account has been deactivated.', 'error')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        
        if not session.get('is_admin'):
            flash('Access denied. Admin only.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# --- Auth Routes ---

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        if session.get('is_admin'):
            return redirect(url_for('admin_interface'))
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            
            if auth_response.user:
                user_id = auth_response.user.id
                profile = get_public_profile(user_id)
                
                # Create profile if missing (legacy fix)
                if not profile:
                    profile = {
                        'id': user_id, 
                        'email': email, 
                        'name': email.split('@')[0],
                        'is_admin': False,
                        'is_active': True
                    }
                    supabase.table('users').insert(profile).execute()

                if not profile.get('is_active', True):
                    supabase.auth.sign_out()
                    flash('Your account has been deactivated. Contact admin.', 'error')
                    return render_template('login.html')

                if profile.get('is_admin', False):
                    # --- ADMIN 2FA FLOW ---
                    # 1. Generate Code
                    code = ''.join(random.choices(string.digits, k=6))
                    
                    # 2. Store in session (temp)
                    session['pre_2fa_user_id'] = user_id
                    session['pre_2fa_profile'] = profile
                    session['admin_2fa_code'] = code # Store expected code
                    
                    # 3. Send Email
                    email_sent = send_2fa_email(email, code)
                    
                    if email_sent:
                        flash(f"Verification code sent to {email}", 'success')
                    else:
                        flash("Could not send email. Check server logs for code (Dev Mode).", 'warning')

                    return render_template('login_2fa.html')
                
                # Standard User Success
                session['user_id'] = user_id
                session['email'] = auth_response.user.email
                session['name'] = profile.get('name')
                session['is_admin'] = False
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))
                
        except Exception as e:
            flash(f"Login failed: {str(e)}", 'error')

    return render_template('login.html')

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    code_input = request.form.get('code')
    
    user_id = session.get('pre_2fa_user_id')
    profile = session.get('pre_2fa_profile')
    expected_code = session.get('admin_2fa_code')
    
    if not user_id: 
        return redirect(url_for('login'))
    
    if code_input == expected_code:
        # Clear temp session vars
        session.pop('pre_2fa_user_id', None)
        session.pop('pre_2fa_profile', None)
        session.pop('admin_2fa_code', None)
        
        # Log in admin
        session['user_id'] = user_id
        session['email'] = profile.get('email')
        session['name'] = profile.get('name')
        session['is_admin'] = True
        
        flash('Admin authentication verified.', 'success')
        return redirect(url_for('admin_interface'))
    else:
        flash('Invalid verification code. Please try again.', 'error')
        return render_template('login_2fa.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        try:
            res = supabase.auth.sign_up({
                "email": email, "password": password, "options": {"data": {"name": name}}
            })
            if res.user:
                new_profile = {
                    'id': res.user.id,
                    'email': email,
                    'name': name,
                    'is_admin': False,
                    'is_active': True
                }
                supabase.table('users').insert(new_profile).execute()
                flash('Registration successful! Please check your email to verify.', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')

    return render_template('register.html')

@app.route('/logout')
def logout():
    supabase.auth.sign_out()
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

# --- Shared Settings Route ---

@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    # 1. Update Name
    if 'name' in request.form:
        new_name = request.form.get('name')
        if new_name:
            # Update public table
            supabase.table('users').update({'name': new_name}).eq('id', user_id).execute()
            session['name'] = new_name
            flash('Profile details updated.', 'success')

    # 2. Update Password
    if 'new_password' in request.form:
        new_pw = request.form.get('new_password')
        confirm_pw = request.form.get('confirm_password')
        
        if new_pw:
            if new_pw == confirm_pw:
                try:
                    # Update password via Supabase Admin API
                    # Note: This works best if you use the SERVICE_ROLE key in .env
                    supabase.auth.admin.update_user_by_id(user_id, {"password": new_pw})
                    flash('Password changed successfully.', 'success')
                except Exception as e:
                    flash(f'Error updating password: {e}', 'error')
            else:
                flash('Passwords do not match.', 'error')

    if is_admin:
        return redirect(url_for('admin_interface'))
    return redirect(url_for('profile'))

# --- Student Routes ---

@app.route('/index')
@login_required
def index():
    user_id = session['user_id']
    schools_res = supabase.table('schools').select('*').execute()
    schools = schools_res.data
    fav_res = supabase.table('favorites').select('school_id').eq('user_id', user_id).execute()
    fav_ids = [item['school_id'] for item in fav_res.data]
    for s in schools: s['is_fav'] = s['id'] in fav_ids
    return render_template('index.html', schools=schools)

@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    user = get_public_profile(user_id)
    return render_template('profile.html', user=user)

@app.route('/api/toggle_favorite', methods=['POST'])
@login_required
def toggle_favorite():
    school_id = request.json.get('school_id')
    user_id = session['user_id']
    existing = supabase.table('favorites').select('*').eq('user_id', user_id).eq('school_id', school_id).execute()
    if existing.data:
        supabase.table('favorites').delete().eq('user_id', user_id).eq('school_id', school_id).execute()
        status = 'removed'
    else:
        supabase.table('favorites').insert({'user_id': user_id, 'school_id': school_id}).execute()
        status = 'added'
    return jsonify({'status': status})

@app.route('/api/view_school', methods=['POST'])
@login_required
def view_school():
    school_id = request.json.get('school_id')
    s_res = supabase.table('schools').select('views').eq('id', school_id).execute()
    if s_res.data:
        new_views = s_res.data[0].get('views', 0) + 1
        supabase.table('schools').update({'views': new_views}).eq('id', school_id).execute()
        return jsonify({'views': new_views})
    return jsonify({'error': 'Not found'})

# --- Admin Routes ---

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_interface():
    # Handle Add OR Edit School
    if request.method == 'POST':
        # Check if this is a school form submission
        if 'name' in request.form: 
            school_id = request.form.get('school_id') # Hidden field
            
            data = {
                'name': request.form.get('name'),
                'type': request.form.get('type'),
                'place': request.form.get('place'),
                'address': request.form.get('address'),
                'lat': float(request.form.get('lat') or 0),
                'lng': float(request.form.get('lng') or 0),
                'tuition': request.form.get('tuition'),
                'programs': request.form.get('programs'),
                'img': request.form.get('img') or "https://via.placeholder.com/400x200",
                'desc': request.form.get('desc'),
                'slots': request.form.get('slots'),
                'link': request.form.get('link'),
                'contact': request.form.get('contact'),
                'socials': request.form.get('socials'),
            }

            if school_id:
                supabase.table('schools').update(data).eq('id', school_id).execute()
                flash('School updated successfully.', 'success')
            else:
                data['views'] = 0
                supabase.table('schools').insert(data).execute()
                flash('School added successfully.', 'success')
            
            return redirect(url_for('admin_interface'))

    # Fetch Data
    schools = supabase.table('schools').select('*').order('created_at', desc=True).execute().data
    users = supabase.table('users').select('*').execute().data
    
    total_users = len(users)
    total_schools = len(schools)
    most_viewed = sorted(schools, key=lambda x: x.get('views', 0), reverse=True)[:3]
    
    # Current admin details
    current_admin = get_public_profile(session['user_id'])

    return render_template('admin_interface.html', 
                           schools=schools, 
                           users=users, 
                           stats={'users': total_users, 'schools': total_schools},
                           most_viewed=most_viewed,
                           admin_user=current_admin)

@app.route('/admin/ban_user/<email>')
@admin_required
def admin_ban_user(email):
    try:
        u_res = supabase.table('users').select('*').eq('email', email).single().execute()
        if u_res.data:
            new_status = not u_res.data.get('is_active', True)
            supabase.table('users').update({'is_active': new_status}).eq('email', email).execute()
            flash(f'User status updated.', 'success')
    except Exception as e:
        flash(f"Error: {e}", 'error')
    return redirect(url_for('admin_interface'))

@app.route('/admin/delete_school/<school_id>')
@admin_required
def admin_delete_school(school_id):
    supabase.table('schools').delete().eq('id', school_id).execute()
    flash('School deleted.', 'success')
    return redirect(url_for('admin_interface'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)