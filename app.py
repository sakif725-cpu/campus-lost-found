from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'admin-secret-key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def is_user_logged_in():
    return session.get('user_id') is not None


def is_admin_logged_in():
    return session.get('role') == 'admin'

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')

    cursor.execute("PRAGMA table_info(users)")
    user_columns = [column[1] for column in cursor.fetchall()]
    if 'full_name' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
    if 'student_id' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN student_id TEXT")
    if 'department' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN department TEXT")
    if 'email' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if 'phone' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT NOT NULL,
            date TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT DEFAULT 'Not Claimed',
            image TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            comment_text TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(item_id) REFERENCES items(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute("PRAGMA table_info(items)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'image' not in columns:
        cursor.execute("ALTER TABLE items ADD COLUMN image TEXT")
    if 'owner_user_id' not in columns:
        cursor.execute("ALTER TABLE items ADD COLUMN owner_user_id INTEGER")

    cursor.execute("SELECT id FROM users WHERE username = ?", ('admin',))
    admin_user = cursor.fetchone()
    if not admin_user:
        admin_password_hash = generate_password_hash('admin123')
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('admin', admin_password_hash, 'admin')
        )
    
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if not is_user_logged_in():
        return redirect('/login')

    search_query = request.args.get('search', '').strip()
    item_filter = request.args.get('filter', '').strip()
    allowed_filters = {'Lost', 'Found'}
    active_filter = item_filter if item_filter in allowed_filters else 'All'

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    query = """
        SELECT
            items.*, 
            COALESCE(NULLIF(users.full_name, ''), users.username, 'Unknown Student') AS student_name
        FROM items
        LEFT JOIN users ON items.owner_user_id = users.id
    """
    conditions = []
    params = []

    if search_query:
        conditions.append("(items.title LIKE ? OR items.description LIKE ?)")
        keyword = f"%{search_query}%"
        params.extend([keyword, keyword])

    if active_filter in allowed_filters:
        conditions.append("items.type = ?")
        params.append(active_filter)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY items.id DESC"
    cursor.execute(query, params)

    items = cursor.fetchall()

    item_ids = [item[0] for item in items]
    comments_by_item_id = {}

    if item_ids:
        placeholders = ','.join(['?'] * len(item_ids))
        comment_query = f'''
            SELECT
                comments.item_id,
                comments.comment_text,
                comments.created_at,
                comments.user_id,
                COALESCE(NULLIF(users.full_name, ''), users.username, 'Unknown Student') AS commenter_name
            FROM comments
            LEFT JOIN users ON comments.user_id = users.id
            WHERE comments.item_id IN ({placeholders})
            ORDER BY comments.id ASC
        '''
        cursor.execute(comment_query, item_ids)
        all_comments = cursor.fetchall()

        for comment in all_comments:
            comments_by_item_id.setdefault(comment[0], []).append(comment)

    conn.close()

    return render_template(
        'index.html',
        items=items,
        comments_by_item_id=comments_by_item_id,
        current_filter=active_filter,
        search_query=search_query,
        username=session.get('username')
    )

@app.route('/add', methods=['POST'])
def add_item():
    if not is_user_logged_in():
        return redirect('/login')
    
    title = request.form['title']
    description = request.form['description']
    location = request.form['location']
    date = request.form['date']
    item_type = request.form['type']
    image = request.files['image']
    image_filename = None

    if image and image.filename != "":
        image_filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO items (title, description, location, date, type, image, owner_user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (title, description, location, date, item_type, image_filename, session.get('user_id')))
    
    conn.commit()
    conn.close()
    
    return redirect('/')

@app.route('/claim/<int:item_id>', methods=['POST'])
def claim_item(item_id):
    if not is_user_logged_in():
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT owner_user_id FROM items WHERE id = ?", (item_id,))
    item = cursor.fetchone()

    if item:
        owner_user_id = item[0]
        current_user_id = session.get('user_id')
        if session.get('role') == 'admin' or owner_user_id == current_user_id:
            cursor.execute("UPDATE items SET status='Claimed' WHERE id=?", (item_id,))
    
    conn.commit()
    conn.close()
    
    return redirect('/')

@app.route('/comment/<int:item_id>', methods=['POST'])
def add_comment(item_id):
    if not is_user_logged_in():
        return redirect('/login')

    comment_text = request.form.get('comment_text', '').strip()
    if not comment_text:
        return redirect('/')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM items WHERE id = ?", (item_id,))
    item = cursor.fetchone()

    if item:
        cursor.execute(
            "INSERT INTO comments (item_id, user_id, comment_text) VALUES (?, ?, ?)",
            (item_id, session.get('user_id'), comment_text)
        )
        conn.commit()

    conn.close()
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_user_logged_in():
        return redirect('/')

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        student_id = request.form.get('student_id', '').strip()
        department = request.form.get('department', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()

        if not username or not password:
            error = 'Username and password are required'
            return render_template('register.html', error=error)

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            error = 'Username already exists'
            return render_template('register.html', error=error)

        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, password, role, full_name, student_id, department, email, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (username, password_hash, 'user', full_name, student_id, department, email, phone)
        )
        conn.commit()
        conn.close()

        return redirect('/login')

    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_user_logged_in():
        return redirect('/')

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            return redirect('/')

        error = 'Invalid username or password'

    return render_template('login.html', error=error)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not is_user_logged_in():
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    success = None

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        student_id = request.form.get('student_id', '').strip()
        department = request.form.get('department', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()

        cursor.execute(
            '''
            UPDATE users
            SET full_name = ?, student_id = ?, department = ?, email = ?, phone = ?
            WHERE id = ?
            ''',
            (full_name, student_id, department, email, phone, session.get('user_id'))
        )
        conn.commit()
        success = 'Profile updated successfully'

    cursor.execute(
        "SELECT username, role, full_name, student_id, department, email, phone FROM users WHERE id = ?",
        (session.get('user_id'),)
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        session.clear()
        return redirect('/login')

    return render_template('profile.html', user=user, success=success)


@app.route('/users/<int:user_id>')
def view_user_profile(user_id):
    if not is_user_logged_in():
        return redirect('/login')

    if user_id == session.get('user_id'):
        return redirect('/profile')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, full_name, student_id, department, email, phone FROM users WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        return redirect('/')

    return render_template('user_profile.html', user=user)

@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin_logged_in():
        return redirect('/login')

    item_filter = request.args.get('filter', '').strip()
    allowed_filters = {'Lost', 'Found'}
    active_filter = item_filter if item_filter in allowed_filters else 'All'

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    query = """
        SELECT
            items.id,
            items.title,
            items.description,
            items.location,
            items.type,
            items.status,
            items.image,
            COALESCE(NULLIF(users.full_name, ''), users.username, 'Unknown Student') AS student_name
        FROM items
        LEFT JOIN users ON items.owner_user_id = users.id
    """
    params = []

    if active_filter in allowed_filters:
        query += " WHERE items.type = ?"
        params.append(active_filter)

    query += " ORDER BY items.id DESC"
    cursor.execute(query, params)
    items = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', items=items, current_filter=active_filter)

@app.route('/admin/delete/<int:item_id>', methods=['POST'])
def admin_delete(item_id):
    if not is_admin_logged_in():
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM comments WHERE item_id = ?", (item_id,))
    cursor.execute("DELETE FROM items WHERE id=?", (item_id,))
    conn.commit()
    conn.close()

    return redirect('/admin/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)