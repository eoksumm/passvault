from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from run_init_db import init_db
from user import register_user, login_user
from vault import add_password, get_passwords
from security import generate_random_password

app = Flask(__name__)
# Secret key for session and CSRF protection
app.config['SECRET_KEY'] = 'A_super_secret_key_123'
csrf = CSRFProtect(app)

# Make sure database is made
init_db()

@app.route('/')
def index():
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    passwords = get_passwords(session['user_id'], session['master_password'], session['salt'])
    return render_template('index.html', passwords=passwords, username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if register_user(username, password):
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        else:
            flash("Username already taken. Try another.")
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = login_user(username, password)
        if user_data:
            session['user_id'] = user_data['id']
            session['username'] = username
            session['master_password'] = password 
            session['salt'] = user_data['salt']
            return redirect(url_for('index'))
        else:
            flash("Wrong username or password.")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        service = request.form['service_name']
        username = request.form['service_username']
        password = request.form['password']
        
        add_password(session['user_id'], session['master_password'], session['salt'], service, username, password)
        flash("Password saved successfully!")
        return redirect(url_for('index'))
        
    return render_template('add.html')

@app.route('/generate', methods=['GET'])
def generate():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    new_password = generate_random_password(16)
    return render_template('generate.html', new_password=new_password)

if __name__ == '__main__':
    app.run(debug=True)
