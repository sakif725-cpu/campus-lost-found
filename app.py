from flask import Flask, render_template, request, redirect, session, jsonify, url_for
import sqlite3
import os
import uuid
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'admin-secret-key')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MESSAGE_MEDIA_FOLDER'] = 'static/messages'
app.config['PROFILE_IMAGE_FOLDER'] = 'static/profile_photos'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['MESSAGE_MEDIA_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_IMAGE_FOLDER'], exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_AUDIO_EXTENSIONS = {'mp3', 'wav', 'ogg', 'm4a', 'webm', 'aac'}


def is_allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def save_message_media(file_storage, allowed_extensions):
    if not file_storage or file_storage.filename == '':
        return None

    if not is_allowed_file(file_storage.filename, allowed_extensions):
        return None

    original_name = secure_filename(file_storage.filename)
    unique_name = f"{uuid.uuid4().hex}_{original_name}"
    file_storage.save(os.path.join(app.config['MESSAGE_MEDIA_FOLDER'], unique_name))
    return unique_name


def is_user_logged_in():
    return session.get('user_id') is not None


def is_admin_logged_in():
    return session.get('role') == 'admin'


def get_unread_message_count(user_id):
    if not user_id:
        return 0

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0",
        (user_id,)
    )
    unread_count = cursor.fetchone()[0]
    conn.close()
    return unread_count


@app.context_processor
def inject_unread_message_count():
    user_id = session.get('user_id')
    unread_messages_count = get_unread_message_count(user_id) if user_id else 0
    return {'unread_messages_count': unread_messages_count}

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
    if 'profile_image' not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_image TEXT")
    
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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS item_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            viewed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(item_id, user_id),
            FOREIGN KEY(item_id) REFERENCES items(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            item_id INTEGER,
            message_text TEXT NOT NULL,
            message_type TEXT DEFAULT 'text',
            media_filename TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_read INTEGER DEFAULT 0,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id),
            FOREIGN KEY(item_id) REFERENCES items(id)
        )
    ''')

    cursor.execute("PRAGMA table_info(messages)")
    message_columns = [column[1] for column in cursor.fetchall()]
    if 'message_type' not in message_columns:
        cursor.execute("ALTER TABLE messages ADD COLUMN message_type TEXT DEFAULT 'text'")
    if 'media_filename' not in message_columns:
        cursor.execute("ALTER TABLE messages ADD COLUMN media_filename TEXT")

    cursor.execute("PRAGMA table_info(items)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'image' not in columns:
        cursor.execute("ALTER TABLE items ADD COLUMN image TEXT")
    if 'owner_user_id' not in columns:
        cursor.execute("ALTER TABLE items ADD COLUMN owner_user_id INTEGER")
    if 'bounty_amount' not in columns:
        cursor.execute("ALTER TABLE items ADD COLUMN bounty_amount REAL")

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

init_db()

@app.route('/')
def home():
    if not is_user_logged_in():
        return redirect('/login')

    current_user_id = session.get('user_id')

    search_query = request.args.get('search', '').strip()
    item_filter = request.args.get('filter', '').strip()
    allowed_filters = {'Lost', 'Found', 'Claimed'}
    active_filter = item_filter if item_filter in allowed_filters else 'All'

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    query = """
        SELECT
            items.id,
            items.title,
            items.description,
            items.location,
            items.date,
            items.type,
            items.status,
            items.image,
            items.owner_user_id,
            COALESCE(NULLIF(users.full_name, ''), users.username, 'Unknown Student') AS student_name,
            items.bounty_amount,
            users.profile_image
        FROM items
        LEFT JOIN users ON items.owner_user_id = users.id
    """
    conditions = []
    params = []

    if search_query:
        conditions.append("(items.title LIKE ? OR items.description LIKE ?)")
        keyword = f"%{search_query}%"
        params.extend([keyword, keyword])

    if active_filter in ('Lost', 'Found'):
        conditions.append("items.type = ?")
        params.append(active_filter)
    elif active_filter == 'Claimed':
        conditions.append("items.status = ?")
        params.append('Claimed')

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY items.id DESC"
    cursor.execute(query, params)

    items = cursor.fetchall()

    item_ids = [item[0] for item in items]
    post_view_counts = {}
    comments_by_item_id = {}

    if item_ids:
        cursor.executemany(
            "INSERT OR IGNORE INTO item_views (item_id, user_id) VALUES (?, ?)",
            [(item_id, current_user_id) for item_id in item_ids]
        )
        conn.commit()

        placeholders = ','.join(['?'] * len(item_ids))
        view_query = f'''
            SELECT item_id, COUNT(*) AS total_views
            FROM item_views
            WHERE item_id IN ({placeholders})
            GROUP BY item_id
        '''
        cursor.execute(view_query, item_ids)
        post_view_counts = {row[0]: row[1] for row in cursor.fetchall()}

        comment_query = f'''
            SELECT
                comments.item_id,
                comments.id,
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
        post_view_counts=post_view_counts,
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
    bounty_amount_text = request.form.get('bounty_amount', '').strip()
    image = request.files['image']
    image_filename = None
    bounty_amount = None

    if item_type == 'Lost' and bounty_amount_text:
        try:
            bounty_amount = round(float(bounty_amount_text), 2)
            if bounty_amount < 0:
                bounty_amount = None
        except ValueError:
            bounty_amount = None

    if image and image.filename != "":
        image_filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO items (title, description, location, date, type, image, owner_user_id, bounty_amount)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (title, description, location, date, item_type, image_filename, session.get('user_id'), bounty_amount))
    
    conn.commit()
    conn.close()
    
    return redirect('/')


@app.route('/edit/<int:item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    if not is_user_logged_in():
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, title, description, location, date, type, image, owner_user_id, bounty_amount FROM items WHERE id = ?",
        (item_id,)
    )
    item = cursor.fetchone()

    if not item:
        conn.close()
        return redirect('/')

    current_user_id = session.get('user_id')
    if session.get('role') != 'admin' and item[7] != current_user_id:
        conn.close()
        return redirect('/')

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        location = request.form.get('location', '').strip()
        date = request.form.get('date', '').strip()
        item_type = request.form.get('type', '').strip()
        bounty_amount_text = request.form.get('bounty_amount', '').strip()
        bounty_amount = None

        if not title or not description or not location or not date or item_type not in ('Lost', 'Found'):
            conn.close()
            return render_template('edit_item.html', item=item, error='Please fill all fields correctly.')

        if item_type == 'Lost' and bounty_amount_text:
            try:
                bounty_amount = round(float(bounty_amount_text), 2)
                if bounty_amount < 0:
                    conn.close()
                    return render_template('edit_item.html', item=item, error='Bounty amount must be 0 or more.')
            except ValueError:
                conn.close()
                return render_template('edit_item.html', item=item, error='Please enter a valid bounty amount.')

        image = request.files.get('image')
        image_filename = item[6]

        if image and image.filename != "":
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        cursor.execute(
            '''
            UPDATE items
            SET title = ?, description = ?, location = ?, date = ?, type = ?, image = ?, bounty_amount = ?
            WHERE id = ?
            ''',
            (title, description, location, date, item_type, image_filename, bounty_amount, item_id)
        )
        conn.commit()
        conn.close()
        return redirect('/')

    conn.close()
    return render_template('edit_item.html', item=item, error=None)

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


@app.route('/delete/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if not is_user_logged_in():
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT owner_user_id FROM items WHERE id = ?", (item_id,))
    item = cursor.fetchone()

    if not item:
        conn.close()
        return redirect('/')

    owner_user_id = item[0]
    current_user_id = session.get('user_id')
    if session.get('role') != 'admin' and owner_user_id != current_user_id:
        conn.close()
        return redirect('/')

    cursor.execute("DELETE FROM comments WHERE item_id = ?", (item_id,))
    cursor.execute("DELETE FROM item_views WHERE item_id = ?", (item_id,))
    cursor.execute("UPDATE messages SET item_id = NULL WHERE item_id = ?", (item_id,))
    cursor.execute("DELETE FROM items WHERE id = ?", (item_id,))

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


@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if not is_user_logged_in():
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT user_id FROM comments WHERE id = ?", (comment_id,))
    comment = cursor.fetchone()

    if comment:
        comment_owner_user_id = comment[0]
        current_user_id = session.get('user_id')
        if session.get('role') == 'admin' or str(comment_owner_user_id) == str(current_user_id):
            cursor.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
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
        profile_photo = request.files.get('profile_photo')
        profile_image_filename = None

        if profile_photo and profile_photo.filename:
            if is_allowed_file(profile_photo.filename, ALLOWED_IMAGE_EXTENSIONS):
                original_name = secure_filename(profile_photo.filename)
                profile_image_filename = f"{uuid.uuid4().hex}_{original_name}"
                profile_photo.save(os.path.join(app.config['PROFILE_IMAGE_FOLDER'], profile_image_filename))

        if profile_image_filename:
            cursor.execute(
                '''
                UPDATE users
                SET full_name = ?, student_id = ?, department = ?, email = ?, phone = ?, profile_image = ?
                WHERE id = ?
                ''',
                (full_name, student_id, department, email, phone, profile_image_filename, session.get('user_id'))
            )
        else:
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
        "SELECT username, role, full_name, student_id, department, email, phone, profile_image FROM users WHERE id = ?",
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
        "SELECT id, username, full_name, student_id, department, email, phone, profile_image FROM users WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        return redirect('/')

    return render_template('user_profile.html', user=user)


@app.route('/inbox')
def inbox():
    if not is_user_logged_in():
        return redirect('/login')

    current_user_id = session.get('user_id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT
            partner_id,
            MAX(id) AS last_message_id,
            SUM(CASE WHEN receiver_id = ? AND is_read = 0 THEN 1 ELSE 0 END) AS unread_count
        FROM (
            SELECT
                id,
                sender_id,
                receiver_id,
                is_read,
                CASE
                    WHEN sender_id = ? THEN receiver_id
                    ELSE sender_id
                END AS partner_id
            FROM messages
            WHERE sender_id = ? OR receiver_id = ?
        )
        GROUP BY partner_id
        ORDER BY last_message_id DESC
        ''',
        (current_user_id, current_user_id, current_user_id, current_user_id)
    )
    conversation_rows = cursor.fetchall()

    conversations = []
    for row in conversation_rows:
        partner_id, last_message_id, unread_count = row

        cursor.execute(
            "SELECT id, username, full_name FROM users WHERE id = ?",
            (partner_id,)
        )
        partner = cursor.fetchone()
        if not partner:
            continue

        cursor.execute(
            "SELECT sender_id, message_text, created_at, message_type, media_filename FROM messages WHERE id = ?",
            (last_message_id,)
        )
        last_message = cursor.fetchone()
        if not last_message:
            continue

        last_message_text = last_message[1] or ''
        if last_message[3] == 'image':
            last_message_text = '[Photo]'
        elif last_message[3] == 'audio':
            last_message_text = '[Voice message]'

        conversations.append({
            'partner_id': partner[0],
            'partner_username': partner[1],
            'partner_name': partner[2] or partner[1],
            'last_sender_id': last_message[0],
            'last_message_text': last_message_text,
            'last_message_time': last_message[2],
            'unread_count': unread_count or 0
        })

    conn.close()
    return render_template('inbox.html', conversations=conversations, current_user_id=current_user_id)


@app.route('/chat/<int:user_id>')
def chat(user_id):
    if not is_user_logged_in():
        return redirect('/login')

    current_user_id = session.get('user_id')
    if user_id == current_user_id:
        return redirect('/inbox')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, full_name FROM users WHERE id = ?",
        (user_id,)
    )
    partner = cursor.fetchone()

    if not partner:
        conn.close()
        return redirect('/inbox')

    requested_item_id = request.args.get('item_id', '').strip()
    chat_item = None
    chat_item_id = None
    if requested_item_id.isdigit():
        chat_item_id = int(requested_item_id)
        cursor.execute("SELECT id, title FROM items WHERE id = ?", (chat_item_id,))
        chat_item = cursor.fetchone()
        if not chat_item:
            chat_item_id = None

    cursor.execute(
        '''
        SELECT id, sender_id, receiver_id, message_text, created_at, item_id, message_type, media_filename
        FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY id ASC
        ''',
        (current_user_id, user_id, user_id, current_user_id)
    )
    messages = cursor.fetchall()

    cursor.execute(
        "UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0",
        (user_id, current_user_id)
    )
    conn.commit()
    conn.close()

    return render_template(
        'chat.html',
        partner=partner,
        messages=messages,
        current_user_id=current_user_id,
        chat_item=chat_item,
        chat_item_id=chat_item_id
    )


@app.route('/chat/<int:user_id>/messages')
def chat_messages(user_id):
    if not is_user_logged_in():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    current_user_id = session.get('user_id')
    if user_id == current_user_id:
        return jsonify({'ok': False, 'error': 'Invalid chat target'}), 400

    after_id_text = request.args.get('after_id', '0').strip()
    after_id = int(after_id_text) if after_id_text.isdigit() else 0

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    partner = cursor.fetchone()
    if not partner:
        conn.close()
        return jsonify({'ok': False, 'error': 'User not found'}), 404

    cursor.execute(
        '''
        SELECT id, sender_id, receiver_id, message_text, created_at, item_id, message_type, media_filename
        FROM messages
        WHERE id > ?
          AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ORDER BY id ASC
        ''',
        (after_id, current_user_id, user_id, user_id, current_user_id)
    )
    rows = cursor.fetchall()

    cursor.execute(
        "UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0",
        (user_id, current_user_id)
    )
    conn.commit()
    conn.close()

    formatted_messages = []
    for row in rows:
        media_url = None
        if row[7]:
            media_url = url_for('static', filename='messages/' + row[7])

        formatted_messages.append({
            'id': row[0],
            'sender_id': row[1],
            'message_text': row[3],
            'created_at': row[4],
            'item_id': row[5],
            'message_type': row[6],
            'media_url': media_url
        })

    return jsonify({'ok': True, 'messages': formatted_messages})


@app.route('/chat/<int:user_id>/send', methods=['POST'])
def send_message(user_id):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if not is_user_logged_in():
        if is_ajax:
            return jsonify({'ok': False, 'redirect_url': '/login'}), 401
        return redirect('/login')

    current_user_id = session.get('user_id')
    if user_id == current_user_id:
        if is_ajax:
            return jsonify({'ok': False, 'redirect_url': '/inbox'}), 400
        return redirect('/inbox')

    message_text = request.form.get('message_text', '').strip()
    item_id_text = request.form.get('item_id', '').strip()
    image_file = request.files.get('image_file')
    audio_file = request.files.get('audio_file')
    item_id = None
    if item_id_text.isdigit():
        item_id = int(item_id_text)

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    receiver = cursor.fetchone()
    if not receiver:
        conn.close()
        if is_ajax:
            return jsonify({'ok': False, 'redirect_url': '/inbox'}), 404
        return redirect('/inbox')

    if item_id is not None:
        cursor.execute("SELECT id FROM items WHERE id = ?", (item_id,))
        item_exists = cursor.fetchone()
        if not item_exists:
            item_id = None

    message_type = 'text'
    media_filename = None

    saved_image = save_message_media(image_file, ALLOWED_IMAGE_EXTENSIONS)
    saved_audio = save_message_media(audio_file, ALLOWED_AUDIO_EXTENSIONS)

    if saved_image:
        message_type = 'image'
        media_filename = saved_image
    elif saved_audio:
        message_type = 'audio'
        media_filename = saved_audio

    inserted_message_id = None
    if message_text or media_filename:
        cursor.execute(
            "INSERT INTO messages (sender_id, receiver_id, item_id, message_text, message_type, media_filename) VALUES (?, ?, ?, ?, ?, ?)",
            (current_user_id, user_id, item_id, message_text, message_type, media_filename)
        )
        inserted_message_id = cursor.lastrowid
        conn.commit()

    sent_message = None
    if inserted_message_id:
        cursor.execute(
            "SELECT id, sender_id, message_text, created_at, item_id, message_type, media_filename FROM messages WHERE id = ?",
            (inserted_message_id,)
        )
        row = cursor.fetchone()
        if row:
            media_url = None
            if row[6]:
                media_url = url_for('static', filename='messages/' + row[6])
            sent_message = {
                'id': row[0],
                'sender_id': row[1],
                'message_text': row[2],
                'created_at': row[3],
                'item_id': row[4],
                'message_type': row[5],
                'media_url': media_url
            }

    conn.close()

    if is_ajax:
        if sent_message:
            return jsonify({'ok': True, 'message': sent_message})
        return jsonify({'ok': False, 'error': 'Empty message'}), 400

    if item_id is not None:
        return redirect(f'/chat/{user_id}?item_id={item_id}')
    return redirect(f'/chat/{user_id}')

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
    cursor.execute("DELETE FROM item_views WHERE item_id = ?", (item_id,))
    cursor.execute("UPDATE messages SET item_id = NULL WHERE item_id = ?", (item_id,))
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)