from flask import Flask, render_template, request, redirect, session, url_for, flash
from db import get_connection
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['WTF_CSRF_ENABLED'] = False

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'user' not in session:
                return redirect('/login')
            if role and session['user']['role'] != role:
                return redirect('/dashboard')
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/')
def home():
    if 'user' not in session:
        return redirect('/login')

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name, message FROM testimonials ORDER BY created_at DESC LIMIT 6")
    testimonials = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('home.html', testimonials=testimonials)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        location = request.form['location'].strip()
        role = request.form.get('role', 'user')
       
        hashed_password = generate_password_hash(password)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (name, email, password, role, location)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, email, hashed_password, role, location))
        conn.commit()
        cursor.close()
        conn.close()

        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE LOWER(email)=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'location': user.get('location', 'Unknown')  # Add location if available
            }
            return redirect('/')
        else:
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if 'user' not in session:
        return redirect('/login')

    if request.method == 'POST':
        session.pop('user', None)
        flash("You have been logged out.")
        return redirect('/login')

    return render_template('logout.html')


@app.route('/dashboard')
@login_required()
def dashboard():
    user = session['user']
    role = user['role']

    if role == 'admin':
        return render_template('admin_dashboard.html', user=user)
    elif role == 'provider':
        return render_template('provider_dashboard.html', user=user)

    location = user.get('location', '')
    user_id = user['id']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT s.title, s.description, s.price, u.name AS provider_name
        FROM services s
        JOIN users u ON s.provider_id = u.id
        WHERE u.location = %s
        ORDER BY s.created_at DESC LIMIT 6
    """, (location,))
    nearby_services = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('dashboard.html', user=user, services=nearby_services)

@app.route('/notifications')
@login_required()
def show_notifications():
    user_id = session['user']['id']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT message, created_at
        FROM notifications
        WHERE user_id IS NULL OR user_id = %s
        ORDER BY created_at DESC
    """, (user_id,))
    notifications = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('notifications.html', notifications=notifications)


@app.route('/providers')
@login_required()
def list_providers():
    role = session['user']['role']
    user_location = session['user'].get('location')
    query = request.args.get('q', '').strip()
    location_filter = request.args.get('location', '').strip()

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    if role == 'admin':
        sql = "SELECT name, email, location FROM users WHERE role = 'provider'"
        params = []

        if query:
            sql += " AND (name LIKE %s OR email LIKE %s)"
            like = f"%{query}%"
            params += [like, like]

        if location_filter:
            sql += " AND location = %s"
            params.append(location_filter)

        sql += " ORDER BY location, name"
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        grouped = {}
        for row in rows:
            loc = row['location'] or 'Unknown'
            grouped.setdefault(loc, []).append(row)

        cursor.execute("SELECT DISTINCT location FROM users WHERE role = 'provider'")
        locations = [r['location'] for r in cursor.fetchall() if r['location']]

        cursor.close()
        conn.close()
        return render_template('providers.html', is_admin=True, grouped_providers=grouped,
                               query=query, selected_location=location_filter, locations=locations)

    else:
        sql = "SELECT name, email, location FROM users WHERE role = 'provider' AND location = %s"
        params = [user_location]

        if query:
            sql += " AND (name LIKE %s OR email LIKE %s)"
            like = f"%{query}%"
            params += [like, like]

        sql += " ORDER BY name"
        cursor.execute(sql, params)
        providers = cursor.fetchall()

        cursor.close()
        conn.close()
        return render_template('providers.html', is_admin=False, providers=providers, query=query)

@app.route('/provider-orders', methods=['GET', 'POST'])
@login_required(role='provider')
def provider_orders():
    provider_id = session['user']['id']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        booking_id = request.form.get('booking_id')
        cursor.execute("""
            UPDATE bookings SET status = 'Confirmed'
            WHERE id = %s AND service_id IN (SELECT id FROM services WHERE provider_id = %s)
        """, (booking_id, provider_id))

        cursor.execute("""
            SELECT user_id FROM bookings WHERE id = %s
        """, (booking_id,))
        result = cursor.fetchone()
        if result:
            user_id = result['user_id']
            message = "🎉 Your booking has been confirmed by the provider!"
            cursor.execute("""
                INSERT INTO notifications (user_id, message) VALUES (%s, %s)
            """, (user_id, message))

        conn.commit()

    cursor.execute("""
        SELECT b.id, b.status, b.booking_time, u.name AS user_name, u.email AS user_email,
               s.title AS service_title
        FROM bookings b
        JOIN services s ON b.service_id = s.id
        JOIN users u ON b.user_id = u.id
        WHERE s.provider_id = %s
        ORDER BY b.booking_time DESC
    """, (provider_id,))
    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('provider_orders.html', orders=orders)

@app.route('/profile')
@login_required()
def profile():
    user_id = session['user']['id']
    role = session['user']['role']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT name, email, role, location FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    extra_data = {}

    if role == 'provider':
        cursor.execute("SELECT COUNT(*) AS count FROM services WHERE provider_id = %s", (user_id,))
        extra_data['service_count'] = cursor.fetchone()['count']
    elif role == 'user':
        cursor.execute("SELECT COUNT(*) AS count FROM bookings WHERE user_id = %s", (user_id,))
        extra_data['booking_count'] = cursor.fetchone()['count']

    cursor.close()
    conn.close()

    return render_template('profile.html', user=user, extra=extra_data)


@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required()
def edit_profile():
    user_id = session['user']['id']

    if request.method == 'POST':
        new_name = request.form['name']
        new_password = request.form['password']
        new_location = request.form['location']

        hashed_pw = generate_password_hash(new_password)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET name=%s, password=%s, location=%s WHERE id=%s
        """, (new_name, hashed_pw, new_location, user_id))
        conn.commit()
        cursor.close()
        conn.close()

        session['user']['name'] = new_name
        session['user']['location'] = new_location

        flash("Profile updated successfully!")
        return redirect('/dashboard')

    return render_template('edit_profile.html', user=session['user'])

@app.route('/add-service', methods=['GET', 'POST'])
@login_required(role='provider')
def add_service():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        provider_id = session['user']['id']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO services (provider_id, title, description, price)
            VALUES (%s, %s, %s, %s)
        """, (provider_id, title, description, price))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Service added successfully!")
        return redirect('/dashboard')

    return render_template('add_service.html')

@app.route('/services')
def all_services():
    query = request.args.get('q', '')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')

    sql = """
        SELECT s.id, s.title, s.description, s.price, s.created_at,
               u.id AS provider_id, u.name AS provider_name, u.email AS provider_email, u.location AS provider_location
        FROM services s
        JOIN users u ON s.provider_id = u.id
        WHERE 1 = 1
    """
    params = []

    if query:
        sql += " AND (s.title LIKE %s OR s.description LIKE %s)"
        like_query = f"%{query}%"
        params.extend([like_query, like_query])

    if min_price:
        sql += " AND s.price >= %s"
        params.append(min_price)

    if max_price:
        sql += " AND s.price <= %s"
        params.append(max_price)

    if 'user' in session and session['user'].get('location'):
        sql += " AND u.location = %s"
        params.append(session['user']['location'])

    sql += " ORDER BY s.created_at DESC"

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, params)
    services = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('services.html', services=services, query=query, min_price=min_price, max_price=max_price)

@app.route('/my-services')
@login_required(role='provider')
def my_services():
    provider_id = session['user']['id']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, title, description, price, created_at
        FROM services
        WHERE provider_id = %s
        ORDER BY created_at DESC
    """, (provider_id,))
    my_services = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('my_services.html', services=my_services)

@app.route('/edit-service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    if 'user' not in session or session['user']['role'] != 'provider':
        return redirect('/login')

    provider_id = session['user']['id']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM services WHERE id=%s AND provider_id=%s", (service_id, provider_id))
    service = cursor.fetchone()

    if not service:
        cursor.close()
        conn.close()
        flash("Service not found or unauthorized.")
        return redirect('/my-services')

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        cursor.execute("""
            UPDATE services
            SET title=%s, description=%s, price=%s
            WHERE id=%s AND provider_id=%s
        """, (title, description, price, service_id, provider_id))

        conn.commit()
        cursor.close()
        conn.close()

        flash("Service updated successfully!")
        return redirect('/my-services')

    cursor.close()
    conn.close()
    return render_template('edit_service.html', service=service)

@app.route('/delete-service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    if 'user' not in session or session['user']['role'] != 'provider':
        return redirect('/login')

    provider_id = session['user']['id']

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM services WHERE id=%s AND provider_id=%s", (service_id, provider_id))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Service deleted successfully!")
    return redirect('/my-services')


@app.route('/my-bookings')
@login_required(role='user')
def my_bookings():
    user_id = session['user']['id']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT b.booking_time, s.title, s.description, s.price,
               u.name AS provider_name, u.email AS provider_email
        FROM bookings b
        JOIN services s ON b.service_id = s.id
        JOIN users u ON s.provider_id = u.id
        WHERE b.user_id = %s
        ORDER BY b.booking_time DESC
    """, (user_id,))
    bookings = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('my_bookings.html', bookings=bookings)

@app.route('/inbox')
@login_required(role='provider')
def inbox():
    provider_id = session['user']['id']

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT m.message, m.sent_at, u.name AS sender_name, u.email AS sender_email
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.receiver_id = %s
        ORDER BY m.sent_at DESC
    """, (provider_id,))
    messages = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('inbox.html', messages=messages)

@app.route('/book/<int:service_id>', methods=['POST'])
@login_required(role='user')
def book_service(service_id):
    user_id = session['user']['id']

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO bookings (user_id, service_id) VALUES (%s, %s)
    """, (user_id, service_id))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Service booked successfully!")
    return redirect('/my-bookings')

@app.route('/contact/<int:provider_id>', methods=['GET', 'POST'])
@login_required(role='user')
def contact_provider(provider_id):
    if request.method == 'POST':
        message_text = request.form['message']
        sender_id = session['user']['id']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, message)
            VALUES (%s, %s, %s)
        """, (sender_id, provider_id, message_text))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Message sent to provider!")
        return redirect('/services')

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name, email FROM users WHERE id = %s", (provider_id,))
    provider = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('contact_provider.html', provider=provider)

@app.route('/admin_dashboard')
@login_required(role='admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/admin_users')
@login_required(role='admin')
def admin_users():
    query = request.args.get('q', '').strip()
    role = request.args.get('role', '')

    sql = "SELECT id, name, email, role FROM users WHERE 1=1"
    params = []

    if query:
        sql += " AND (name LIKE %s OR email LIKE %s)"
        like = f"%{query}%"
        params.extend([like, like])

    if role:
        sql += " AND role = %s"
        params.append(role)

    sql += " ORDER BY id DESC"

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, params)
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('admin/admin_users.html', users=users, query=query, role=role)


@app.route('/admin/admin_services')
@login_required(role='admin')
def admin_services():
    query = request.args.get('q', '').strip()
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')

    sql = """
        SELECT s.id, s.title, s.description, s.price,
               u.name AS provider
        FROM services s
        JOIN users u ON s.provider_id = u.id
        WHERE 1=1
    """
    params = []

    if query:
        sql += " AND (s.title LIKE %s OR s.description LIKE %s OR u.name LIKE %s)"
        like = f"%{query}%"
        params.extend([like, like, like])

    if min_price:
        sql += " AND s.price >= %s"
        params.append(min_price)

    if max_price:
        sql += " AND s.price <= %s"
        params.append(max_price)

    sql += " ORDER BY s.id DESC"

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, params)
    services = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('admin/admin_services.html', services=services, query=query, min_price=min_price, max_price=max_price)


@app.route('/admin/admin_contacts')
@login_required(role='admin')
def admin_contacts():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM contacts ORDER BY created_at DESC")
    contacts = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('admin/admin_contacts.html', contacts=contacts)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("User deleted successfully!")
    return redirect('/admin/admin_users')

@app.route('/admin/delete_service/<int:service_id>', methods=['POST'])
@login_required(role='admin')
def admin_delete_service(service_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM services WHERE id = %s", (service_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Service deleted successfully!")
    return redirect('/admin/admin_services')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO contacts (name, email, message)
            VALUES (%s, %s, %s)
        """, (name, email, message))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Thanks for contacting us! We'll get back to you soon.")
        return redirect('/contact')

    return render_template('contact.html')


if __name__ == '__main__':
    app.run(debug=True)
