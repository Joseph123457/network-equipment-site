from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import sqlite3
import os
import requests
import random

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # 보안 키, 나중에 변경하세요

# DB 초기화
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS equipment
                 (id INTEGER PRIMARY KEY, name TEXT, manufacturer TEXT, category TEXT, specs TEXT, image TEXT, upload_date TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS spec_items
                 (id INTEGER PRIMARY KEY, item_name TEXT UNIQUE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    # 기본 관리자 계정
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password')")
    # 기본 스펙 항목
    default_specs = ['throughput', 'vpn_throughput', 'concurrent_sessions', 'cpu', 'memory', 'ports', 'power_supply']
    for spec in default_specs:
        c.execute("INSERT OR IGNORE INTO spec_items (item_name) VALUES (?)", (spec,))
    conn.commit()
    conn.close()

init_db()

# 사용자 클래스
class User(UserMixin):
    pass

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User()

# 로그인 폼
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Telegram OTP 보내기 함수 (나중에 사용)
def send_otp_to_telegram(chat_id, token, otp):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': f"Your OTP: {otp}"}
    response = requests.post(url, json=payload)
    print(f"Telegram API Response: {response.status_code} - {response.text}")
    return response

# 메인 페이지
@app.route('/')
def index():
    return render_template('index.html')

# 검색
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').lower()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # 스펙 값만 검색하도록 specs 컬럼에서 키 제외
    c.execute("SELECT * FROM equipment WHERE LOWER(name) LIKE ? OR LOWER(manufacturer) LIKE ? OR LOWER(specs) LIKE ?",
              (f'%{query}%', f'%{query}%', f'%{query}%'))
    results = c.fetchall()
    conn.close()
    # 스펙 키(항목 이름)는 검색에서 제외하기 위해 필터링
    filtered_results = []
    for result in results:
        specs = eval(result[4]) if result[4] else {}
        if (query in result[1].lower() or query in result[2].lower() or
            any(query in str(value).lower() for value in specs.values())):
            filtered_results.append(result)
    return render_template('search.html', results=filtered_results)
    

# 관리자 로그인 (OTP 우회)
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (form.username.data, form.password.data))
        user = c.fetchone()
        conn.close()
        if user:
            user_obj = User()
            user_obj.id = form.username.data
            login_user(user_obj)
            flash('Logged in successfully (OTP skipped for testing).')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html', form=form)

# 관리자 대시보드
@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin.html')

# 로그아웃
@app.route('/admin/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# 신규 장비 등록
@app.route('/admin/add_equipment', methods=['GET', 'POST'])
@login_required
def add_equipment():
    if request.method == 'POST':
        name = request.form['name']
        manufacturer = request.form['manufacturer']
        category = request.form['category']
        upload_date = request.form['upload_date']
        image = request.files['image'].filename if 'image' in request.files else ''
        # 스펙 처리: 배열 형태로 전송된 이름과 값 처리
        specs = {}
        spec_names = request.form.getlist('spec_name[]')
        spec_values = request.form.getlist('spec_value[]')
        for name, value in zip(spec_names, spec_values):
            if value:  # 값이 입력된 경우만 저장
                specs[name] = value
        specs_str = str(specs)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO equipment (name, manufacturer, category, specs, image, upload_date) VALUES (?, ?, ?, ?, ?, ?)",
                  (name, manufacturer, category, specs_str, image, upload_date))
        conn.commit()
        conn.close()
        if image:
            request.files['image'].save(os.path.join('static/uploads', image))
        return redirect(url_for('admin_dashboard'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT item_name FROM spec_items")
    spec_items = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('add_equipment.html', spec_items=spec_items)

# 스펙 항목 관리
@app.route('/admin/manage_specs', methods=['GET', 'POST'])
@login_required
def manage_specs():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if request.method == 'POST':
        action = request.form['action']
        item_name = request.form['item_name']
        if action == 'add':
            c.execute("INSERT OR IGNORE INTO spec_items (item_name) VALUES (?)", (item_name,))
        elif action == 'delete':
            c.execute("DELETE FROM spec_items WHERE item_name=?", (item_name,))
        conn.commit()
    c.execute("SELECT item_name FROM spec_items")
    spec_items = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('manage_specs.html', spec_items=spec_items)

# 장비 상세
@app.route('/equipment/<int:id>')
def equipment_detail(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM equipment WHERE id=?", (id,))
    equip = c.fetchone()
    conn.close()
    specs = eval(equip[4]) if equip[4] else {}
    return render_template('detail.html', equip=equip, specs=specs)

if __name__ == '__main__':
    os.makedirs('static/uploads', exist_ok=True)
    app.run(debug=True)