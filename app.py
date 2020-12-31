from flask import Flask, render_template, g, request, redirect, flash, session, url_for, abort
from database import connect_db, get_db
from flask_bcrypt import Bcrypt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '6ca3de84328c0830e0baaa8207b187ec'
bcrypt = Bcrypt(app)


def get_current_user():
    if 'user' in session:
        db = get_db()
        cur = db.cursor()
        cur.execute("""SELECT id, name, password, expert, admin
                    FROM users
                    WHERE name=?""", (session['user'],))
        user_data = cur.fetchone()

        user_dict = dict()
        user_dict['id'] = user_data['id']
        user_dict['name'] = user_data['name']
        user_dict['password'] = user_data['password']
        if user_data['expert'] == 0 and user_data['admin'] == 0:
            user_dict['type'] = 'user'
        elif user_data['expert'] == 1:
            user_dict['type'] = 'expert'
        elif user_data['expert'] == 0 and user_data['admin'] == 1:
            user_dict['type'] = 'admin'
        return user_dict


def user_check(route):
    @wraps(route)
    def wrapper(*args, **kwargs):
        if 'user' in session and get_current_user()['type'] == 'user':
            return route(*args, **kwargs)
        else:
            abort(403)

    return wrapper


def expert_check(route):
    @wraps(route)
    def wrapper(*args, **kwargs):
        print('expert check executed')
        if 'user' in session and get_current_user()['type'] == 'expert':
            print(get_current_user()['type'])
            return route(*args, **kwargs)
        else:
            abort(403)

    return wrapper


def admin_check(route):
    @wraps(route)
    def wrapper(*args, **kwargs):
        if 'user' in session and get_current_user()['type'] == 'admin':
            return route(*args, **kwargs)
        else:
            abort(403)

    return wrapper


def if_logged_check(route):
    @wraps(route)
    def wrapper(*args, **kwargs):
        if 'user' in session:
            return redirect(url_for('home'))

        return route(*args, **kwargs)
    return wrapper


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


@app.route('/')
@app.route('/home')
def home():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    cur.execute("""SELECT questions.id, 
                askers.name AS asker, 
                experts.name AS expert, 
                questions.question_text, 
                questions.answer_text
                FROM questions 
                JOIN users AS askers ON questions.user_id = askers.id 
                JOIN users AS experts ON questions.expert_id = experts.id 
                WHERE questions.answer_text IS NOT NULL""")
    questions = cur.fetchall()
    return render_template('home.html', user=user, questions=questions)


@app.route('/register', methods=['GET', 'POST'])
@if_logged_check
def register():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    if request.method == 'POST':
        username = request.form['username']
        cur.execute("""SELECT * FROM users WHERE name=?""", (username,))
        user_exists = cur.fetchall()
        if user_exists:
            return render_template('register.html', user=user, error='This user already exists.')
        password = request.form['password']
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        cur.execute("""INSERT INTO users 
                    (name, password, expert, admin) 
                    values (?, ?, ?, ?)""",
                    (username, pw_hash, 0, 0))
        db.commit()
        session['user'] = username
        flash('Account has been created', 'success')
        return redirect(url_for('home'))

    return render_template('register.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
@if_logged_check
def login():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cur.execute("""SELECT id, name, password FROM users WHERE name=?""", (username,))
        user_data = cur.fetchone()
        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            session['user'] = user_data['name']
            flash(f'Hello {user_data["name"]}. You are now logged in.')
            return redirect(url_for('home'))
        else:
            flash('Invalid password or username', 'danger')
            redirect(url_for('login'))
    return render_template('login.html', user=user)


@app.route('/question/<question_id>')
def question(question_id):
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    cur.execute("""SELECT questions.question_text AS question,
                questions.answer_text AS answer,
                askers.name AS asker,
                experts.name AS expert
                FROM questions
                JOIN users AS askers ON askers.id = questions.user_id
                JOIN users AS experts ON experts.id = questions.expert_id
                WHERE questions.id=?""",
                (question_id,))
    question = cur.fetchone()
    return render_template('question.html', user=user, question=question)


@app.route('/ask', methods=['GET', 'POST'])
@user_check
def ask():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    cur.execute("""SELECT id, name FROM users WHERE expert=1""")
    expert_list = cur.fetchall()
    if request.method == 'POST':
        question_from = user['id']
        question_to = request.form['question_to']
        question_text = request.form['question_text']
        cur.execute("""INSERT INTO questions
                    (user_id, expert_id, question_text)
                    VALUES (?, ?, ?)""",
                    (question_from, question_to, question_text))
        db.commit()
        flash('Question successfully send to chosen expert.')
        return redirect(url_for('home'))
    return render_template('ask.html', user=user, expert_list=expert_list)


@app.route('/answer/<question_id>', methods=['GET', 'POST'])
@expert_check
def answer(question_id):
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    cur.execute("""SELECT question_text AS text FROM questions WHERE id=?""",
                (question_id,))
    question = cur.fetchone()
    if request.method == 'POST':
        answer = request.form['answer']
        cur.execute("""UPDATE questions SET answer_text=? WHERE id=?""",
                    (answer, question_id))
        db.commit()
        flash('Answered added successfully.')
        return redirect(url_for('home'))
    return render_template('answer.html', user=user, question=question)


@app.route('/unanswered')
@expert_check
def unanswered():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    cur.execute("""SELECT
                    questions.id, 
                    questions.user_id, 
                    questions.question_text,
                    users.name 
                FROM questions 
                JOIN users ON questions.user_id = users.id
                WHERE questions.answer_text is NULL AND questions.expert_id=?""",
                (user['id'],))
    questions = cur.fetchall()
    print(questions[0].keys())
    return render_template('unanswered.html', user=user, questions=questions)


@app.route('/users')
@admin_check
def users():
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    cur.execute("""SELECT id, name, expert, admin FROM users""")
    user_list = cur.fetchall()
    return render_template('users.html', user=user, user_list=user_list)


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


@app.route('/promote/<user_id>')
@admin_check
def promote(user_id):
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    cur.execute("""UPDATE users SET expert=1 WHERE id=?""", (user_id, ))
    db.commit()
    return redirect(url_for("users"))


@app.route('/degrade/<user_id>')
@admin_check
def degrade(user_id):
    user = get_current_user()
    db = get_db()
    cur = db.cursor()
    cur.execute("""UPDATE users SET expert=0 WHERE id=?""", (user_id, ))
    db.commit()
    return redirect(url_for("users"))


if __name__ == '__main__':
    app.run()