
from flask import Flask, request, render_template, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_very_secret_key'  # Change this to a more secure key for production

# Setup MySQL connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="youruser",
        password="yourpassword",  # Replace with your actual password
        database="user_system"  # Or "youruser" depending on which database you want to use
    )

@app.route('/')
def index():
    if 'username' in session:
        # User is logged in, show a personalized welcome page
        return render_template('welcome.html', username=session['username'])
    # Not logged in, redirect to login page
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db_connection()
        cursor = db.cursor(buffered=True)
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        db.close()
        if user and check_password_hash(user[0], password):
            session['username'] = username
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        db = get_db_connection()
        cursor = db.cursor(buffered=True)
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            db.commit()
            flash('User created successfully! Please log in.')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Username already exists')
        finally:
            db.close()
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        hashed_password = generate_password_hash(new_password)
        db = get_db_connection()
        cursor = db.cursor()
        try:
            cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
            db.commit()
            flash('Password reset successfully. Please log in with your new password.')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash('Error resetting password: {}'.format(err))
        finally:
            db.close()
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
