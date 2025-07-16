from flask import Blueprint, render_template, request, redirect, url_for, session, flash
import re
from werkzeug.security import generate_password_hash, check_password_hash
from .db import get_db_connection

auth_routes = Blueprint('auth_routes', __name__)

@auth_routes.route('/')
def home():
    return render_template('index.html')

@auth_routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        role = request.form['role']

        if not username or not email or not password or not confirm_password or not role:
            flash('Please fill all fields.', 'danger')
            return redirect(url_for('auth_routes.register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('auth_routes.register'))

        allowed_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "neurona.com"]
        email_domain = email.split('@')[-1].lower()
        if email_domain not in allowed_domains:
            flash(f"Email domain must be one of: {', '.join(allowed_domains)}", 'danger')
            return redirect(url_for('auth_routes.register'))

        if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
            flash('Password must be at least 8 characters and include a special character.', 'danger')
            return redirect(url_for('auth_routes.register'))

        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users(username, email, password, role) VALUES (?, ?, ?, ?)",
                      (username, email, hashed_password, role))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth_routes.login'))
        except:
            flash('Email already exists.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

@auth_routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['email'] = user['email']
            session['role'] = user['role']
            session['verified'] = user['verified']
            return redirect(url_for(f"{user['role']}_routes.{user['role']}_dashboard"))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('auth_routes.login'))

    return render_template('login.html')

@auth_routes.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth_routes.login'))
