from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
import io
import logging

app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

app.logger.setLevel(logging.INFO)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def get_db():
    conn = sqlite3.connect('regias.db')
    conn.row_factory = sqlite3.Row
    return conn

with get_db() as conn:
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, stage_access INTEGER, last_login DATETIME, reset_token TEXT, reset_expiry DATETIME)')
    conn.execute('CREATE TABLE IF NOT EXISTS stages (id INTEGER PRIMARY KEY, stage_number INTEGER, stage_name TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS forms (id INTEGER PRIMARY KEY, stage_id INTEGER, question TEXT, type TEXT, options TEXT, allow_file_upload INTEGER, required INTEGER)')
    conn.execute('CREATE TABLE IF NOT EXISTS parents (id INTEGER PRIMARY KEY, name TEXT, stage_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
    conn.execute('CREATE TABLE IF NOT EXISTS answers (id INTEGER PRIMARY KEY, parent_id INTEGER, form_id INTEGER, answer TEXT, file_path TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
    
    # Admin kullanıcısını ekle
    admin_exists = conn.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'").fetchone()[0]
    if admin_exists == 0:
        hashed_password = generate_password_hash('sekc123')
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hashed_password, 'admin'))
    
    # Başlangıç aşamalarını ekle
    stages_exist = conn.execute("SELECT COUNT(*) FROM stages").fetchone()[0]
    if stages_exist == 0:
        conn.execute("INSERT INTO stages (stage_number, stage_name) VALUES (?, ?)", (1, 'Aşama 1'))
        conn.execute("INSERT INTO stages (stage_number, stage_name) VALUES (?, ?)", (2, 'Aşama 2'))
        conn.execute("INSERT INTO stages (stage_number, stage_name) VALUES (?, ?)", (3, 'Aşama 3'))
        conn.execute("INSERT INTO stages (stage_number, stage_name) VALUES (?, ?)", (4, 'Aşama 4'))
        conn.execute("INSERT INTO stages (stage_number, stage_name) VALUES (?, ?)", (5, 'Aşama 5'))
        
    conn.commit()

class User(UserMixin):
    def __init__(self, id, username, password, role, stage_access):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.stage_access = stage_access

@login_manager.user_loader
def load_user(user_id):
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user:
            return User(user['id'], user['username'], user['password'], user['role'], user['stage_access'])
        return None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        try:
            with get_db() as conn:
                user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                if user and check_password_hash(user['password'], password):
                    user_obj = User(user['id'], user['username'], user['password'], user['role'], user['stage_access'])
                    login_user(user_obj)
                    conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
                    conn.commit()
                    app.logger.info(f"User {username} logged in successfully")
                    if user['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('staff_form'))  # staff_dashboard yerine staff_form
                else:
                    app.logger.info(f"Invalid credentials for {username}")
                    flash('Invalid credentials', 'error')
        except Exception as e:
            app.logger.error(f"Login error for {username}: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (email,)).fetchone()
            if user:
                token = os.urandom(16).hex()
                expiry = 'DATETIME(CURRENT_TIMESTAMP, "+30 minutes")'
                conn.execute('UPDATE users SET reset_token = ?, reset_expiry = ' + expiry + ' WHERE id = ?', (token, user['id']))
                conn.commit()
                msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Click this link to reset your password: {url_for("reset_password_token", token=token, _external=True)}'
                mail.send(msg)
                flash('Reset link sent to your email')
            else:
                flash('Email not found')
    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE reset_token = ? AND reset_expiry > CURRENT_TIMESTAMP', (token,)).fetchone()
        if not user:
            flash('Invalid or expired token')
            return redirect(url_for('login'))
        if request.method == 'POST':
            password = request.form['password']
            conn.execute('UPDATE users SET password = ?, reset_token = NULL, reset_expiry = NULL WHERE id = ?', (generate_password_hash(password), user['id']))
            conn.commit()
            flash('Password reset successfully')
            return redirect(url_for('login'))
    return render_template('reset_password_form.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    with get_db() as conn:
        users = conn.execute('SELECT * FROM users').fetchall()
        stages = conn.execute('SELECT * FROM stages').fetchall()
        parents = conn.execute('SELECT * FROM parents').fetchall()
        forms = conn.execute('SELECT f.*, s.stage_number FROM forms f JOIN stages s ON f.stage_id = s.id').fetchall()
        logs = conn.execute('SELECT l.*, u.username FROM logs l JOIN users u ON l.user_id = u.id').fetchall()
    return render_template('admin_dashboard.html', users=users, stages=stages, parents=parents, forms=forms, logs=logs)

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        stage_access_raw = request.form.get('stage_access', '')
        stage_access = int(stage_access_raw) if stage_access_raw and role == 'staff' else None
        if not username or not password or not role:
            flash('Username, password, and role are required', 'error')
            return redirect(url_for('admin_dashboard'))
        if role == 'staff' and not stage_access_raw:
            flash('Stage access is required for staff', 'error')
            return redirect(url_for('admin_dashboard'))
        
        with get_db() as conn:
            conn.execute('INSERT INTO users (username, password, role, stage_access) VALUES (?, ?, ?, ?)', 
                         (username, generate_password_hash(password), role, stage_access))
            conn.execute('INSERT INTO logs (user_id, action) VALUES (?, ?)', (current_user.id, f'Added user {username}'))
            conn.commit()
        app.logger.info(f"User {username} added successfully by {current_user.username}")
        flash(f'User {username} added successfully', 'success')
    except Exception as e:
        app.logger.error(f"Error adding user: {str(e)}")
        flash(f'Error adding user: {str(e)}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    with get_db() as conn:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.execute('INSERT INTO logs (user_id, action) VALUES (?, ?)', (current_user.id, f'Deleted user {user_id}'))
        conn.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/change_password/<int:user_id>', methods=['POST'])
@login_required
def change_password(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    password = request.form['password']
    with get_db() as conn:
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (generate_password_hash(password), user_id))
        conn.execute('INSERT INTO logs (user_id, action) VALUES (?, ?)', (current_user.id, f'Changed password for user {user_id}'))
        conn.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_stage', methods=['POST'])
@login_required
def add_stage():
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    stage_number = int(request.form['stage_number'])
    stage_name = request.form['stage_name']
    with get_db() as conn:
        conn.execute('INSERT INTO stages (stage_number, stage_name) VALUES (?, ?)', (stage_number, stage_name))
        conn.execute('INSERT INTO logs (user_id, action) VALUES (?, ?)', (current_user.id, f'Added stage {stage_name}'))
        conn.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_stage/<int:stage_id>')
@login_required
def delete_stage(stage_id):
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    with get_db() as conn:
        conn.execute('DELETE FROM stages WHERE id = ?', (stage_id,))
        conn.execute('DELETE FROM forms WHERE stage_id = ?', (stage_id,))
        conn.execute('INSERT INTO logs (user_id, action) VALUES (?, ?)', (current_user.id, f'Deleted stage {stage_id}'))
        conn.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_form', methods=['POST'])
@login_required
def add_form():
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    stage_id = int(request.form['stage_id'])
    question = request.form['question']
    type = request.form['type']
    options = request.form.get('options', '')
    allow_file_upload = 1 if 'allow_file_upload' in request.form else 0
    required = 1 if 'required' in request.form else 0
    with get_db() as conn:
        conn.execute('INSERT INTO forms (stage_id, question, type, options, allow_file_upload, required) VALUES (?, ?, ?, ?, ?, ?)', 
                     (stage_id, question, type, options, allow_file_upload, required))
        conn.execute('INSERT INTO logs (user_id, action) VALUES (?, ?)', (current_user.id, f'Added form question "{question}"'))
        conn.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/staff/form', methods=['GET', 'POST'])
@login_required
def staff_form():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    with get_db() as conn:
        stages = conn.execute('SELECT * FROM stages WHERE stage_number = ?', (current_user.stage_access,)).fetchall()
        if not stages:
            flash('No stages assigned to you')
            return redirect(url_for('logout'))
        forms = conn.execute('SELECT * FROM forms WHERE stage_id = ?', (stages[0]['id'],)).fetchall()
        if request.method == 'POST':
            parent_name = request.form['parent_name']
            conn.execute('INSERT INTO parents (name, stage_id) VALUES (?, ?)', (parent_name, stages[0]['id']))
            parent_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
            for form in forms:
                answer = request.form.get(f'answer_{form["id"]}', '')
                file_path = None
                if form['allow_file_upload'] and f'file_{form["id"]}' in request.files:
                    file = request.files[f'file_{form["id"]}']
                    if file:
                        upload_result = cloudinary.uploader.upload(file)
                        file_path = upload_result['secure_url']
                conn.execute('INSERT INTO answers (parent_id, form_id, answer, file_path) VALUES (?, ?, ?, ?)', 
                             (parent_id, form['id'], answer, file_path))
            conn.commit()
            flash('Form submitted successfully')
            return redirect(url_for('staff_form'))
    return render_template('staff_form.html', stages=stages, forms=forms)

@app.route('/admin/parent/<int:parent_id>')
@login_required
def parent_detail(parent_id):
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    with get_db() as conn:
        parent = conn.execute('SELECT * FROM parents WHERE id = ?', (parent_id,)).fetchone()
        answers = conn.execute('SELECT a.*, f.question, f.type, f.options FROM answers a JOIN forms f ON a.form_id = f.id WHERE a.parent_id = ?', (parent_id,)).fetchall()
        stages = conn.execute('SELECT * FROM stages').fetchall()
    return render_template('parent_detail.html', parent=parent, answers=answers, stages=stages)

@app.route('/admin/report', methods=['GET', 'POST'])
@login_required
def report():
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    search = request.form.get('search', '') if request.method == 'POST' else ''
    with get_db() as conn:
        parents = conn.execute('SELECT p.*, s.stage_name FROM parents p JOIN stages s ON p.stage_id = s.id WHERE p.name LIKE ?', (f'%{search}%',)).fetchall()
    return render_template('report.html', parents=parents, search=search)

@app.route('/admin/report/pdf/<int:parent_id>')
@login_required
def report_pdf(parent_id):
    if current_user.role != 'admin':
        return redirect(url_for('staff_form'))
    with get_db() as conn:
        parent = conn.execute('SELECT * FROM parents WHERE id = ?', (parent_id,)).fetchone()
        answers = conn.execute('SELECT a.*, f.question FROM answers a JOIN forms f ON a.form_id = f.id WHERE a.parent_id = ?', (parent_id,)).fetchall()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph(f"Parent: {parent['name']}", styles['Title']), Spacer(1, 12)]
    data = [['Question', 'Answer']]
    for answer in answers:
        data.append([answer['question'], answer['answer'] or answer['file_path'] or 'N/A'])
    table = Table(data)
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"{parent['name']}_report.pdf")

@app.route('/test-admin')
def test_admin():
    try:
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
            return f"Admin user: {dict(user) if user else 'Not found'}"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
