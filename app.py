from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField, TextAreaField
from wtforms.validators import DataRequired
import sqlite3
import os
import boto3
import requests
import random

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key')

# R2 설정
s3 = boto3.client('s3',
                  endpoint_url=os.getenv('R2_ENDPOINT_URL'),
                  aws_access_key_id=os.getenv('R2_ACCESS_KEY_ID'),
                  aws_secret_access_key=os.getenv('R2_SECRET_KEY_ID'))

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS equipment
                 (id INTEGER PRIMARY KEY, name TEXT, manufacturer TEXT, category TEXT, specs TEXT, image TEXT, datasheet TEXT, certification TEXT, upload_date TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS spec_items
                 (id INTEGER PRIMARY KEY, item_name TEXT UNIQUE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password')")
    default_specs = ['throughput', 'vpn_throughput', 'concurrent_sessions', 'cpu', 'memory', 'ports', 'power_supply']
    for spec in default_specs:
        c.execute("INSERT OR IGNORE INTO spec_items (item_name) VALUES (?)", (spec,))
    conn.commit()
    conn.close()

init_db()

class User(UserMixin):
    pass

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AddEquipmentForm(FlaskForm):
    name = StringField('제품명', validators=[DataRequired()])
    manufacturer = StringField('제조사', validators=[DataRequired()])
    category = SelectField('카테고리', choices=[('전송', '전송'), ('네트워크', '네트워크'), ('보안', '보안'), ('솔루션', '솔루션'), ('전원', '전원')])
    upload_date = StringField('업로드 날짜', validators=[DataRequired()])
    image = FileField('사진')
    datasheet = FileField('데이터시트 (PDF)')
    certification = TextAreaField('인증현황', validators=[DataRequired()])

class EditEquipmentForm(FlaskForm):
    name = StringField('제품명', validators=[DataRequired()])
    manufacturer = StringField('제조사', validators=[DataRequired()])
    category = SelectField('카테고리', choices=[('전송', '전송'), ('네트워크', '네트워크'), ('보안', '보안'), ('솔루션', '솔루션'), ('전원', '전원')])
    upload_date = StringField('업로드 날짜', validators=[DataRequired()])
    image = FileField('사진')
    datasheet = FileField('데이터시트 (PDF)')
    certification = TextAreaField('인증현황', validators=[DataRequired()])

def send_otp_to_telegram(chat_id, token, otp):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': f"Your OTP: {otp}"}
    response = requests.post(url, json=payload)
    print(f"Telegram API Response: {response.status_code} - {response.text}")
    return response

@app.route('/')
def index():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, name, manufacturer, category FROM equipment ORDER BY id DESC LIMIT 5")
    recent_equipment = c.fetchall()
    conn.close()
    return render_template('index.html', recent_equipment=recent_equipment)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').lower()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM equipment WHERE LOWER(name) LIKE ? OR LOWER(manufacturer) LIKE ? OR LOWER(specs) LIKE ?",
              (f'%{query}%', f'%{query}%', f'%{query}%'))
    total = c.fetchone()[0]
    total_pages = (total // per_page) + (1 if total % per_page else 0)
    c.execute("SELECT * FROM equipment WHERE LOWER(name) LIKE ? OR LOWER(manufacturer) LIKE ? OR LOWER(specs) LIKE ? LIMIT ? OFFSET ?",
              (f'%{query}%', f'%{query}%', f'%{query}%', per_page, offset))
    results = c.fetchall()
    conn.close()
    filtered_results = []
    for result in results:
        specs = eval(result[4]) if result[4] else {}
        if (query in result[1].lower() or query in result[2].lower() or
            any(query in str(value).lower() for value in specs.values())):
            filtered_results.append(result)
    return render_template('search.html', results=filtered_results, query=query, page=page, total_pages=total_pages)

@app.route('/compare', methods=['GET'])
def compare():
    selected_ids = request.args.getlist('selected')
    if len(selected_ids) < 2:
        flash('2개 이상의 제품을 선택해주세요.')
        return redirect(url_for('search'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    equipment = []
    for id in selected_ids:
        c.execute("SELECT * FROM equipment WHERE id = ?", (id,))
        equip = c.fetchone()
        specs = eval(equip[4]) if equip[4] else {}
        equipment.append((equip, specs))
    conn.close()
    return render_template('compare.html', equipment=equipment)

@app.route('/category/<category>')
def category(category):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if category == '전체':
        c.execute("SELECT COUNT(*) FROM equipment")
        total = c.fetchone()[0]
        c.execute("SELECT id, name, manufacturer, category FROM equipment ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, offset))
    else:
        c.execute("SELECT COUNT(*) FROM equipment WHERE category = ?", (category,))
        total = c.fetchone()[0]
        c.execute("SELECT id, name, manufacturer, category FROM equipment WHERE category = ? LIMIT ? OFFSET ?", (category, per_page, offset))
    equipment = c.fetchall()
    total_pages = (total // per_page) + (1 if total % per_page else 0)
    conn.close()
    return render_template('category.html', equipment=equipment, category=category, page=page, total_pages=total_pages)

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

@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin.html')

@app.route('/admin/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/add_equipment', methods=['GET', 'POST'])
@login_required
def add_equipment():
    form = AddEquipmentForm()
    if request.method == 'POST' and form.validate_on_submit():
        name = form.name.data
        manufacturer = form.manufacturer.data
        category = form.category.data
        upload_date = form.upload_date.data
        image = form.image.data if form.image.data else None
        datasheet = form.datasheet.data if form.datasheet.data else None
        certification = form.certification.data
        image_url = ''
        datasheet_url = ''
        if image:
            image_filename = image.filename
            s3.upload_fileobj(image, 'equipment-images', image_filename)
            image_url = f"{os.getenv('R2_ENDPOINT_URL')}/equipment-images/{image_filename}"
        if datasheet:
            datasheet_filename = datasheet.filename
            s3.upload_fileobj(datasheet, 'equipment-datasheets', datasheet_filename)
            datasheet_url = f"{os.getenv('R2_ENDPOINT_URL')}/equipment-datasheets/{datasheet_filename}"
        specs = {}
        spec_names = request.form.getlist('spec_name[]')
        spec_values = request.form.getlist('spec_value[]')
        for name, value in zip(spec_names, spec_values):
            if value:
                specs[name] = value
        specs_str = str(specs)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO equipment (name, manufacturer, category, specs, image, datasheet, certification, upload_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (name, manufacturer, category, specs_str, image_url, datasheet_url, certification, upload_date))
        conn.commit()
        conn.close()
        flash('등록이 완료되었습니다.')
        return redirect(url_for('admin_dashboard'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT item_name FROM spec_items")
    spec_items = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('add_equipment.html', form=form, spec_items=spec_items)

@app.route('/admin/manage_specs', methods=['GET', 'POST'])
@login_required
def manage_specs():
    if request.method == 'POST':
        action = request.form['action']
        item_name = request.form['item_name']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        if action == 'add':
            c.execute("INSERT OR IGNORE INTO spec_items (item_name) VALUES (?)", (item_name,))
        elif action == 'delete':
            c.execute("DELETE FROM spec_items WHERE item_name=?", (item_name,))
        conn.commit()
        conn.close()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT item_name FROM spec_items")
    spec_items = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('manage_specs.html', spec_items=spec_items)

@app.route('/equipment/<int:id>')
def equipment_detail(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM equipment WHERE id=?", (id,))
    equip = c.fetchone()
    conn.close()
    specs = eval(equip[4]) if equip[4] else {}
    return render_template('detail.html', equip=equip, specs=specs)

@app.route('/admin/equipment_list', methods=['GET', 'POST'])
@login_required
def equipment_list():
    if request.method == 'POST':
        selected_ids = request.form.getlist('selected')
        if selected_ids:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.executemany("DELETE FROM equipment WHERE id = ?", [(id,) for id in selected_ids])
            conn.commit()
            conn.close()
            flash('선택한 장비가 삭제되었습니다.')
        return redirect(url_for('equipment_list'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, name, manufacturer, category FROM equipment")
    equipment = c.fetchall()
    conn.close()
    return render_template('equipment_list.html', equipment=equipment)

@app.route('/admin/edit_equipment/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_equipment(id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM equipment WHERE id = ?", (id,))
    equip = c.fetchone()
    if not equip:
        flash('장비를 찾을 수 없습니다.')
        return redirect(url_for('equipment_list'))
    specs = eval(equip[4]) if equip[4] else {}

    c.execute("SELECT item_name FROM spec_items")
    spec_items = [row[0] for row in c.fetchall()]
    conn.close()

    form = EditEquipmentForm()
    if request.method == 'POST' and form.validate_on_submit():
        name = form.name.data
        manufacturer = form.manufacturer.data
        category = form.category.data
        upload_date = form.upload_date.data
        image = form.image.data if form.image.data else None
        image_url = equip[5]  # 기존 이미지 유지
        if image:
            image_filename = image.filename
            s3.upload_fileobj(image, 'equipment-images', image_filename)
            image_url = f"{os.getenv('R2_ENDPOINT_URL')}/equipment-images/{image_filename}"
        specs = {}
        spec_names = request.form.getlist('spec_name[]')
        spec_values = request.form.getlist('spec_value[]')
        for name, value in zip(spec_names, spec_values):
            if value:
                specs[name] = value
        specs_str = str(specs)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE equipment SET name = ?, manufacturer = ?, category = ?, specs = ?, image = ?, upload_date = ? WHERE id = ?",
                  (name, manufacturer, category, specs_str, image_url, upload_date, id))
        conn.commit()
        conn.close()
        flash('장비 정보가 수정되었습니다.')
        return redirect(url_for('equipment_list'))

    form.name.data = equip[1]
    form.manufacturer.data = equip[2]
    form.category.data = equip[3]
    form.upload_date.data = equip[6]
    return render_template('edit_equipment.html', form=form, specs=specs, spec_items=spec_items, current_image=equip[5])

if __name__ == '__main__':
    os.makedirs('static/uploads', exist_ok=True)
    app.run(debug=True)