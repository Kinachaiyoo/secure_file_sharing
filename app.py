# The above code is a Python script that includes various imports and defines a Flask application.
# Here is a breakdown of what the code is doing:
from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import os
import secrets
import uuid
import shutil
from utils.crypto_utils import generate_user_keys, issue_certificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from datetime import datetime
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from flask import send_from_directory



app = Flask(__name__, static_url_path="/static", static_folder="uploaded_docs")


app.secret_key = 'supersecretkey'
DATABASE = "database/app.db"

# Ensure database directory exists
os.makedirs("database", exist_ok=True)

# Create necessary folders
os.makedirs("uploaded_docs", exist_ok=True)
os.makedirs("signed_docs", exist_ok=True)
os.makedirs("verified_results", exist_ok=True)

# Ensure all required tables exist
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    position TEXT NOT NULL,
    password TEXT NOT NULL,
    login_token TEXT,
    status TEXT DEFAULT 'pending',
    comment TEXT DEFAULT ''
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_name TEXT NOT NULL,
    signed_by TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    comment TEXT DEFAULT ''
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS shared_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    filename TEXT NOT NULL,
    password TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/select')
def select():
    return render_template('select.html')

@app.route('/user')
def user_home():
    return render_template('user.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        email = request.form['email']
        position = request.form['position']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if not email.endswith('@crypto.com'):
            flash("Only company email (@crypto.com) is allowed.", "error")
            return redirect('/register')
        elif password != confirm:
            flash("Passwords do not match.", "error")
            return redirect('/register')
        elif (not any(c.isdigit() for c in password) or
              not any(c.isalpha() for c in password) or
              not any(c in '!@#$%^&*()_+-=' for c in password)):
            flash("Password must include letter, number, and special symbol.", "error")
            return redirect('/register')
        else:
            conn = get_db_connection()
            try:
                login_token = secrets.token_hex(16)

                conn.execute("""
                    INSERT INTO users (fullname, username, email, position, password, login_token)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (fullname, username, email, position, password, login_token))
                conn.commit()

                # Generate keys and certificate internally
                key, _ = generate_user_keys(username)
                issue_certificate(username, fullname, key)

                return render_template("show_token.html", username=username, token=login_token)

            except sqlite3.IntegrityError:
                flash("Username already exists.", "error")
                return redirect('/register')
            finally:
                conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        token = request.form['login_token']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()

        if not user:
            flash("Invalid username or password.", "error")
            return redirect('/login')

        if user['password'] != password:
            flash("Invalid username or password.", "error")
            return redirect('/login')

        if user['login_token'] != token:
            flash("Login token does not match. Possible certificate or identity mismatch.", "error")
            return redirect('/login')

        if user['status'] == 'pending':
            flash("Your account is still pending approval by admin.", "error")
            return redirect('/login')
        elif user['status'] == 'rejected':
            flash(f"Your registration was rejected. Reason: {user['comment']}", "error")
            return redirect('/login')

        # Passed all checks — login successful
        session['user'] = username
        flash("Login successful!", "success")
        return redirect('/user_dashboard')

    return render_template('login.html')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user' not in session:
        return redirect('/login')

    username = session['user']
    conn = get_db_connection()

    # Get received files
    received = conn.execute("""
        SELECT filename, sender FROM shared_files
        WHERE receiver=? AND sender != ?
    """, (username, username)).fetchall()

    # Get sent/shared files
    sent = conn.execute("""
        SELECT filename, receiver FROM shared_files
        WHERE sender=? AND receiver IS NOT NULL
    """, (username,)).fetchall()

    # Get document status
    documents = conn.execute("SELECT doc_name, status, comment FROM documents WHERE signed_by=?", 
                             (username,)).fetchall()

    # Get chat history
    chat_history = conn.execute("""
        SELECT sender, receiver, message FROM chat_logs
        WHERE sender=? OR receiver=?
        ORDER BY id ASC
    """, (username, username)).fetchall()

    # Get all registered users (approved)
    users = conn.execute("SELECT username FROM users WHERE status='approved'").fetchall()
    conn.close()

    return render_template(
        'user_dashboard.html',
        username=username,
        shared_filename=session.pop('shared_filename', None),
        shared_token_file=session.pop('shared_token_file', None),
        received_files=[dict(row) for row in received],
        sent_files=[dict(row) for row in sent],
        user_documents=documents,
        chat_history=[dict(row) for row in chat_history],
        registered_users=[row['username'] for row in users]
    )

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'HR@admin123':
            session['admin'] = True
            return redirect('/admin')
        else:
            flash("Invalid admin credentials.", "error")
            return render_template('admin.html', admin_logged_in=False)

    if not session.get('admin'):
        return render_template('admin.html', admin_logged_in=False)

    conn = get_db_connection()
    pending_users = conn.execute("SELECT * FROM users WHERE status='pending'").fetchall()
    all_users = conn.execute("SELECT * FROM users").fetchall()
    
    #  Add this block to fetch document data
    pending_docs = conn.execute("SELECT * FROM documents WHERE status='pending'").fetchall()
    all_docs = conn.execute("SELECT * FROM documents").fetchall()
    conn.close()

    return render_template(
        'admin.html',
        admin_logged_in=True,
        pending_users=pending_users,
        all_users=all_users,
        pending_docs=pending_docs,
        all_docs=all_docs
    )


@app.route('/admin/approve', methods=['POST'])
def approve_user():
    if not session.get('admin'):
        return redirect('/logout')

    username = request.form['username']
    action = request.form['action']
    comment = request.form.get('comment', '').strip()

    if not comment:
        flash("Comment is required when approving or rejecting a user.", "error")
        return redirect('/admin')

    status = 'approved' if action == 'approve' else 'rejected'

    conn = get_db_connection()
    conn.execute("UPDATE users SET status=?, comment=? WHERE username=? AND status='pending'",
                 (status, comment, username))
    conn.commit()
    conn.close()
    return redirect('/admin')

@app.route('/admin/update_user', methods=['POST'])
def update_user():
    if not session.get('admin'):
        return redirect('/logout')

    username = request.form['username']
    action = request.form['action']

    conn = get_db_connection()
    if action == 'delete':
        conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return redirect('/admin')

@app.route('/admin/documents')
def admin_documents():
    if not session.get('admin'):
        return redirect('/logout')
    
    conn = get_db_connection()
    pending_docs = conn.execute("SELECT * FROM documents WHERE status='pending'").fetchall()
    all_docs = conn.execute("SELECT * FROM documents").fetchall()
    conn.close()

    return render_template("admin_documents.html", pending_docs=pending_docs, all_docs=all_docs)


@app.route('/admin/approve_doc', methods=['POST'])
def approve_document():
    if not session.get('admin'):
        return redirect('/logout')

    doc_name = request.form['doc_name']
    action = request.form['action']
    comment = request.form.get('comment', '').strip()

    if not comment:
        flash("Comment is required for document approval/rejection.", "error")
        return redirect('/admin')

    status = 'approved' if action == 'approve' else 'rejected'

    conn = get_db_connection()
    conn.execute("UPDATE documents SET status=?, comment=? WHERE doc_name=? AND status='pending'",
                 (status, comment, doc_name))
    conn.commit()
    conn.close()
    return redirect('/admin')

@app.route('/admin/delete_doc', methods=['POST'])
def delete_doc():
    if not session.get('admin'):
        return redirect('/logout')

    doc_name = request.form['doc_name']
    try:
        # Delete signature and uploaded file from storage
        os.remove(os.path.join("signed_docs", doc_name + ".sig"))
        os.remove(os.path.join("uploaded_docs", doc_name))
    except FileNotFoundError:
        pass

    conn = get_db_connection()
    conn.execute("DELETE FROM documents WHERE doc_name=?", (doc_name,))
    conn.commit()
    conn.close()

    flash("Document deleted successfully.", "success")
    return redirect('/admin')


@app.route('/view_document/<filename>')
def view_document(filename):
    if not session.get('admin'):
        return redirect('/logout')

    full_path = "uploaded_docs"
    file_path = os.path.join(full_path, filename)
    if not os.path.exists(file_path):
        flash("File not found.", "error")
        return redirect('/admin')

    return send_from_directory(full_path, filename)

@app.route('/send_file', methods=['POST'])
def send_file():
    if 'user' not in session:
        return redirect('/login')

    sender = session['user']
    filename = request.form['filename']
    password = request.form.get('password')

    if not password:
        flash("Password is required to share the file.", "error")
        return redirect('/user_dashboard')

    token = str(uuid.uuid4())

    conn = get_db_connection()

    # Validate document is approved
    doc = conn.execute("SELECT * FROM documents WHERE doc_name=? AND signed_by=? AND status='approved'",
                       (filename, sender)).fetchone()
    if not doc:
        flash("Only approved files can be shared.", "error")
        conn.close()
        return redirect('/user_dashboard')

    # Check if file exists before trying to copy
    original_path = os.path.join("uploaded_docs", filename)
    if not os.path.exists(original_path):
        conn.close()
        flash("File not found. Please re-sign and wait for admin approval again.", "error")
        return redirect('/user_dashboard')

    token_filename = token + "_" + filename
    shared_path = os.path.join("uploaded_docs", token_filename)

    try:
        shutil.copy(original_path, shared_path)
    except Exception as e:
        conn.close()
        flash(f"Error copying file: {str(e)}", "error")
        return redirect('/user_dashboard')

    # Save sharing record
    conn.execute("""
        INSERT INTO shared_files (sender, filename, password, encrypted_path, token)
        VALUES (?, ?, ?, ?, ?)
    """, (sender, filename, password, token_filename, token))
    conn.commit()
    conn.close()

    # Redirect to success page
    return redirect(f'/share_success?token={token}&password={password}')


@app.route('/download_shared', methods=['POST'])
def download_shared():
    if 'user' not in session:
        return redirect('/login')

    token = request.form['token']
    entered_password = request.form.get('password')
    receiver = session['user']

    conn = get_db_connection()
    record = conn.execute("SELECT * FROM shared_files WHERE token=?", (token,)).fetchone()

    if not record:
        conn.close()
        flash("Invalid or expired token.", "error")
        return redirect('/user_dashboard')

    if not entered_password or entered_password != record['password']:
        conn.close()
        flash("Incorrect password.", "error")
        return redirect('/user_dashboard')

    # ✅ Update the record to include receiver if not already set
    if not record['receiver']:
        conn.execute("UPDATE shared_files SET receiver=? WHERE token=?", (receiver, token))
        conn.commit()

    conn.close()

    # Render dashboard with download options
    session['shared_filename'] = record['filename']
    session['shared_token_file'] = record['encrypted_path']
    return redirect('/user_dashboard')


@app.route('/share_success')
def share_success():
    token = request.args.get('token')
    password = request.args.get('password')

    if not token or not password:
        flash("Invalid share link.", "error")
        return redirect('/user_dashboard')

    return render_template('share_success.html', token=token, password=password)

@app.route('/view_shared/<filename>')
def view_shared_file(filename):
    path = os.path.join("uploaded_docs", filename)
    if os.path.exists(path):
        return send_from_directory("uploaded_docs", filename)
    else:
        flash("File not found.", "error")
        return redirect('/user_dashboard')

@app.route('/download_final/<filename>')
def download_final_file(filename):
    display_name = request.args.get('display_name', filename)
    path = os.path.join("uploaded_docs", filename)
    if os.path.exists(path):
        return send_from_directory("uploaded_docs", filename, as_attachment=True,
                                   download_name=display_name)
    else:
        flash("File not found.", "error")
        return redirect('/user_dashboard')

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user' not in session:
        return redirect('/login')

    sender = session['user']
    receiver = request.form.get('receiver')
    message = request.form.get('message')

    if not receiver or not message:
        flash("Receiver and message are required.", "error")
        return redirect('/user_dashboard')

    conn = get_db_connection()
    conn.execute("INSERT INTO chat_logs (sender, receiver, message) VALUES (?, ?, ?)",
                 (sender, receiver, message))
    conn.commit()
    conn.close()

    return redirect('/user_dashboard#chat')



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/sign_document', methods=['POST'])
def sign_document():
    if 'user' not in session:
        return redirect('/login')

    file = request.files['document']
    if not file:
        flash("No file uploaded.", "error")
        return redirect('/user_dashboard')

    username = session['user']
    filename = secure_filename(file.filename)
    filepath = os.path.join("uploaded_docs", filename)
    file.save(filepath)

    # Load user's private key
    try:
        key_path = f"keys/user_keys/{username}_private_key.pem"
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Read file data and sign
        with open(filepath, "rb") as f:
            data = f.read()
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Save signature
        signed_path = os.path.join("signed_docs", filename + ".sig")
        with open(signed_path, "wb") as f:
            f.write(signature)

        # Save to DB (for admin to approve later)
        conn = get_db_connection()
        conn.execute("INSERT INTO documents (doc_name, signed_by, status, comment) VALUES (?, ?, ?, ?)",
                     (filename, username, 'pending', ''))
        conn.commit()
        conn.close()

        flash("Document signed successfully. Awaiting admin approval.", "success")
    except Exception as e:
        flash(f"Error during signing: {str(e)}", "error")

    return redirect('/user_dashboard')


@app.route('/verify_document', methods=['POST'])
def verify_document():
    if 'user' not in session:
        return redirect('/login')

    file = request.files['verify_document']
    if not file:
        flash("No file uploaded for verification.", "error")
        return redirect('/user_dashboard')

    filename = secure_filename(file.filename)
    filepath = os.path.join("uploaded_docs", filename)
    file.save(filepath)

    # Check if signature exists
    sig_path = os.path.join("signed_docs", filename + ".sig")
    if not os.path.exists(sig_path):
        flash("Document signature not found.", "error")
        return redirect('/user_dashboard')

    username = session['user']
    cert_path = f"certs/user_certs/{username}_cert.pem"
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        public_key = cert.public_key()

        with open(filepath, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()

        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Check document status in DB
        conn = get_db_connection()
        row = conn.execute("SELECT status, comment FROM documents WHERE doc_name=? AND signed_by=?",
                           (filename, username)).fetchone()
        conn.close()

        if not row:
            flash("Document not found in approval records.", "error")
        elif row["status"] == "approved":
            flash("✅ Document is signed and approved by admin.", "success")
        elif row["status"] == "rejected":
            flash(f"❌ Document rejected by admin. Reason: {row['comment']}", "error")
        else:
            flash("Document is signed but not yet approved by admin.", "error")

    except Exception as e:
        flash(f"Verification failed: {str(e)}", "error")

    return redirect('/user_dashboard')

@app.context_processor
def inject_document_table():
    if 'user' not in session:
        return {}
    conn = get_db_connection()
    documents = conn.execute("SELECT doc_name, status, comment FROM documents WHERE signed_by=?", 
                             (session['user'],)).fetchall()
    conn.close()
    return dict(user_documents=documents)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
