from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import sqlite3
import os
import requests  # Telegram용
import random  # OTP 생성용

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # 보안 키, 나중에 변경하세요

# DB 초기화
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS equipment
                 (id INTEGER PRIMARY KEY, name TEXT, manufacturer TEXT, category TEXT, specs TEXT, image TEXT, upload_date TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS spec_items
                 (id INTEGER PRIMARY KEY, item_name TEXT UNIQUE)''')  # 스펙 항목 목록 테이블
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    # 기본 관리자 계정 (나중에 변경)
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('ktadmin', 'qwe123!@#')")
    # 기본 스펙 항목 추가 (참고 사이트 기반)
    default_specs = ['throughput', 'vpn_throughput', 'concurrent_sessions', 'cpu', 'memory', 'ports', 'power_supply']
    for spec in default_specs:
        c.execute("INSERT OR IGNORE INTO spec_items (item_name) VALUES (?)", (spec,))
    conn.commit()
    conn.close()

init_db()

# 사용자 클래스 (로그인용)
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

# Telegram OTP 보내기 함수
def send_otp_to_telegram(chat_id, token, otp):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': f"Your OTP: {otp}"}
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        print(f"Telegram API Error: {response.text}")
    return response

# 메인 페이지 (원본 기반, 제목 변경, 인기 목록 삭제)
@app.route('/')
def index():
    return render_template('index.html')

# 검색 기능 (제품명, 제조사, 스펙 검색)
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').lower()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM equipment WHERE LOWER(name) LIKE ? OR LOWER(manufacturer) LIKE ? OR LOWER(specs) LIKE ?",
              (f'%{query}%', f'%{query}%', f'%{query}%'))
    results = c.fetchall()
    conn.close()
    return render_template('search.html', results=results)

# 관리자 로그인 (ID/PW + Telegram OTP)
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

# OTP 확인 페이지
# @app.route('/admin/login', methods=['GET', 'POST'])
# def admin_login():
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

# 신규 장비 등록 (수동 모드만, 자동 모드 생략)
@app.route('/admin/add_equipment', methods=['GET', 'POST'])
@login_required
def add_equipment():
    if request.method == 'POST':
        name = request.form['name']
        manufacturer = request.form['manufacturer']
        category = request.form['category']
        upload_date = request.form['upload_date']  # 현재 날짜 입력
        image = request.files['image'].filename if 'image' in request.files else ''
        # 스펙 처리: 선택된 항목과 값
        specs = {}
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT item_name FROM spec_items")
        all_specs = [row[0] for row in c.fetchall()]
        for spec in all_specs:
            value = request.form.get(spec, '')
            if value:
                specs[spec] = value
        specs_str = str(specs)  # DB에 문자열로 저장
        c.execute("INSERT INTO equipment (name, manufacturer, category, specs, image, upload_date) VALUES (?, ?, ?, ?, ?, ?)",
                  (name, manufacturer, category, specs_str, image, upload_date))
        conn.commit()
        conn.close()
        # 이미지 저장
        if image:
            request.files['image'].save(os.path.join('static/uploads', image))
        return redirect(url_for('admin_dashboard'))
    # 스펙 항목 목록 불러오기
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT item_name FROM spec_items")
    spec_items = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('add_equipment.html', spec_items=spec_items)

# 스펙 항목 관리 (추가/수정/삭제)
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

# 장비 상세 페이지 (Copy 버튼, 업로드 날짜, 가격 삭제)
@app.route('/equipment/<int:id>')
def equipment_detail(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM equipment WHERE id=?", (id,))
    equip = c.fetchone()
    conn.close()
    specs = eval(equip[4]) if equip[4] else {}  # 문자열을 딕셔너리로 변환
    return render_template('detail.html', equip=equip, specs=specs)

if __name__ == '__main__':
    os.makedirs('static/uploads', exist_ok=True)  # 이미지 폴더
    app.run(debug=True)