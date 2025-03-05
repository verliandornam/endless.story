import os
from flask import *
from flask_cors import CORS
from openai import OpenAI
import pymysql
import bcrypt
from config import host, user, password, db_name

db_config = {
    'host': host,
    'port': 3307,
    'user': user,
    'password': password,
    'database': db_name,
    'cursorclass': pymysql.cursors.DictCursor
}

try:
    connection = pymysql.connect(**db_config)
    print("Connected...!")

    try:
        with connection.cursor() as cursor:
            print("-" * 20)
                
    finally:
        connection.close()

except Exception as ex:
    print("Connection failed...")
    print(ex)

client = OpenAI(
    base_url="https://models.inference.ai.azure.com",
    api_key="your_key",
)

def hash_password(plain_password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed

def check_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

app = Flask(__name__)
app.secret_key = 'yourkey'
CORS(app)

@app.route('/')
def main_page():
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT p.genre, u.username 
                FROM playcount p
                LEFT JOIN users u ON p.lastuserid = u.id
            """)
            playcount_data = {row["genre"]: row["username"] or "Unknown" for row in cursor.fetchall()}

    finally:
        connection.close()
    return render_template('main.html', username=session.get('username'), credits=session.get('credits'), playcount_data=playcount_data)

@app.route('/reg-auth')
def regauth():
    session.clear()
    return render_template('regauth.html')

@app.route('/fantasy')
def fantasy():
    if 'userid' not in session:
        return redirect(url_for('main_page'))
    return render_template('fantasy.html', username=session.get('username'), credits=session.get('credits'), userid=session.get('userid'))

@app.route('/sci-fi')
def scifi():
    if 'userid' not in session:
        return redirect(url_for('main_page'))
    return render_template('scifi.html', username=session.get('username'), credits=session.get('credits'), userid=session.get('userid'))

@app.route('/post-apocalyptic')
def postapocalyptic():
    if 'userid' not in session:
        return redirect(url_for('main_page'))
    return render_template('postapocalyptic.html', username=session.get('username'), credits=session.get('credits'), userid=session.get('userid'))

@app.route('/pirates')
def pirates():
    if 'userid' not in session:
        return redirect(url_for('main_page'))
    return render_template('pirates.html', username=session.get('username'), credits=session.get('credits'), userid=session.get('userid'))

@app.route('/space-civilization')
def spacecivilization():
    if 'userid' not in session:
        return redirect(url_for('main_page'))
    return render_template('spacecivilization.html', username=session.get('username'), credits=session.get('credits'), userid=session.get('userid'))

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            try:
                connection = pymysql.connect(**db_config)
                with connection.cursor() as cursor:
                    check_query = "SELECT id FROM `users` WHERE username = %s;"
                    cursor.execute(check_query, (username,))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        return "<h1>User already exists!</h1>", 409
                    
                    hashed_password = hash_password(password)
                    
                    insert_query = "INSERT INTO `users` (username, password, credits) VALUES (%s, %s, %s);"
                    cursor.execute(insert_query, (username, hashed_password, 100))
                    connection.commit()
                    
                    select_query = "SELECT * FROM `users` WHERE username=%s;"
                    cursor.execute(select_query, (username,))
                    user = cursor.fetchone()

                    session['userid'] = user['id']
                    session['username'] = user['username']
                    session['credits'] = user['credits']
                    print(f"Added one new user: {username}")
            finally:
                connection.close()
            return redirect(url_for('main_page'))
        else:
            return "<h1>Please fill in all fields!</h1>", 400
    return ""


@app.route('/login_user', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username and password:
            try:
                connection = pymysql.connect(**db_config)
                with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                    select_query = "SELECT * FROM `users` WHERE username=%s;"
                    cursor.execute(select_query, (username,))
                    user = cursor.fetchone()

                    if user:
                        hashed_password = user['password'].encode('utf-8')
                        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                            session['userid'] = user['id']
                            session['username'] = user['username']
                            session['credits'] = user['credits']
                            print(f"User {username} successfully logged in.")
                            return redirect(url_for('main_page'))
                        else:
                            return "<h1>Incorrect password!</h1>", 401
                    else:
                        return "<h1>Username not found!</h1>", 404

            except Exception as e:
                print(f"Error: {e}")
                return "<h1>Server error. Try again later.</h1>", 500

            finally:
                connection.close()

        else:
            return "<h1>Please fill in all fields!</h1>", 400

    return ""

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('main_page'))

@app.route('/check-credits', methods=['POST'])
def check_credits():
    data = request.get_json()

    if 'userid' not in session:
        return redirect(url_for('main_page'))
    userid = session['userid']
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (userid))
            user = cursor.fetchone()
            if not user:
                return redirect(url_for('main_page'))
            if user['credits'] <= 0:
                return jsonify({'success': False, 'error': 'Insufficient credits'}), 400
            else:
                user['credits'] -= 1
                session['credits'] = user['credits']
                cursor.execute(
                    "UPDATE users SET credits = %s WHERE id = %s",
                    (user['credits'], userid)
                )
                connection.commit()
                return jsonify({'success': True, 'credits': user['credits']})
    finally:
        connection.close()

@app.route('/get-response', methods=['POST'])
def get_response():
        
    data = request.get_json()
    user_messages = data.get('messages', [])

    if not user_messages:
        return jsonify({'error': 'Messages are required'}), 400

    try:
        response = client.chat.completions.create(
            messages=user_messages,
            model="gpt-4o",
            temperature=1,
            max_tokens=4096,
            top_p=1
        )

        ai_reply = response.choices[0].message.content
        return jsonify({'reply': ai_reply})

    except Exception as e:
        print(f"OpenAI API Error: {e}")
        return jsonify({'error': 'Error with OpenAI API'}), 500


@app.route('/update_playcount', methods=['POST'])
def update_playcount():
    data = request.json
    userid = session['userid']
    genre = data.get('genre')

    try:
        connection = pymysql.connect(**db_config)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("SELECT * FROM playcount WHERE genre = %s", (genre,))
            row = cursor.fetchone()
            if row:
                new_count = row['count'] + 1
                cursor.execute("UPDATE playcount SET count = %s, lastuserid = %s WHERE genre = %s", (new_count, userid, genre))
            connection.commit()
    finally:
        if connection.open:
            connection.close()

if __name__ == '__main__':
    app.run(port=3000, debug=True)
