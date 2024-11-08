from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# Database path
DATABASE = os.path.join(os.getcwd(), 'instance', 'users.db')

# Function to initialize the database
def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                password TEXT
            )
        ''')
        conn.commit()
        conn.close()

# Initialize the database
init_db()

@app.route('/')
def home():
    if 'user_id' in session:
        # User is logged in, fetch their details
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if user:
            username = user[0]
            return render_template('home.html', username=username)  # Pass username to the template
    return redirect(url_for('login'))  # If not logged in, redirect to login page



# Registration route (GET: display form, POST: process form data)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Hash the password before saving
        hashed_password = generate_password_hash(password)
        
        # Connect to the database and insert user data
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        try:
            c.execute(''' 
                INSERT INTO users (username, email, password) 
                VALUES (?, ?, ?) 
            ''', (username, email, hashed_password))
            conn.commit()
            return redirect(url_for('home'))  # Redirect to home after successful registration
        except sqlite3.IntegrityError:
            return "Username or Email already exists!"  # Error if username or email is already taken
        finally:
            conn.close()
    
    return render_template('register.html')  # Render registration form

# Login route (GET: display form, POST: process form data)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        
        # Connect to the database and check for user
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()  # Get the first matching user
        
        conn.close()
        
        if user:
            # Check if the password is correct
            if check_password_hash(user[3], password):  # user[3] is the hashed password
                # Store user in session
                session['user_id'] = user[0]  # Save user ID in session (for later use)
                return redirect(url_for('home'))  # Redirect to home after successful login
            else:
                return "Incorrect password"
        else:
            return "Username not found"
    
    return render_template('login.html')  # Render login form

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user_id from session
    return redirect(url_for('login'))  # Redirect to login page



# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)

