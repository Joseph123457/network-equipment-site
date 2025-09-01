from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField
from wtforms.validators import DataRequired
import sqlite3
import os
import boto3
import requests
import random
import pdfplumber
import re
from bs4 import BeautifulSoup

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB 제한

# R2 설정
s3 = boto3.client('s3',
                  endpoint_url=os.getenv('R2_ENDPOINT_URL'),
                  aws_access_key_id=os.getenv('R2_ACCESS_KEY_ID'),
                  aws_secret_access_key=os.getenv('R2_SECRET_KEY_ID'))

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS equipment
                 (id INTEGER PRIMARY KEY, name TEXT, manufacturer TEXT, category TEXT, specs TEXT, image TEXT, upload_date TEXT)''')
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
    product_url = StringField('웹페이지 링크')

def parse_datasheet(file):
    try:
        print(f"Processing file: {file.filename}, Size: {file.content_length} bytes")
        if file.content_length > 5 * 1024 * 1024:
            flash("PDF 파일이 너무 큽니다. 5MB 이하로 업로드해주세요.")
            return None
        with pdfplumber.open(file) as pdf:
            text = ''
            for i, page in enumerate(pdf.pages[:10]):  # 최대 10페이지
                page_text = page.extract_text()
                print(f"Page {i+1} text: {page_text}")
                text += page_text or ''
                if len(text) > 100000:  # 텍스트 크기 제한
                    flash("PDF 텍스트가 너무 큽니다. 더 작은 파일을 사용해주세요.")
                    return None
        
        extracted_data = {'name': '', 'manufacturer': '', 'specs': {}}
        print(f"Extracted text: {text[:1000]}...")  # 로그 크기 제한
        
        # 제품명 추출
        name_match = re.search(r'(?:Product Name|Model)\s*[:=]\s*([^\n]+)', text, re.IGNORECASE)
        if name_match:
            extracted_data['name'] = name_match.group(1).strip()
            print(f"Extracted name: {extracted_data['name']}")
        
        # 제조사 추출
        manufacturer_match = re.search(r'(?:Manufacturer|Brand)\s*[:=]\s*([^\n]+)', text, re.IGNORECASE)
        if manufacturer_match:
            extracted_data['manufacturer'] = manufacturer_match.group(1).strip()
            print(f"Extracted manufacturer: {extracted_data['manufacturer']}")
        
        # 스펙 추출
        spec_matches = re.findall(r'(\w+)\s*[:=]\s*([^\n]+)', text, re.IGNORECASE)
        for key, value in spec_matches:
            key = key.lower().strip()
            value = value.strip()
            extracted_data['specs'][key] = value
            print(f"Extracted spec: {key} = {value}")
            try:
                conn = sqlite3.connect('database.db')
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO spec_items (item_name) VALUES (?)", (key,))
                conn.commit()
            except sqlite3.Error as e:
                print(f"SQLite error: {e}")
                flash(f"데이터베이스 오류: {e}")
            finally:
                conn.close()
        
        return extracted_data
    except Exception as e:
        print(f"Error parsing datasheet: {str(e)}")
        flash(f"PDF 처리 중 오류 발생: {str(e)}")
        return None

def parse_product_page(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        extracted_data_list = []
        
        # 여러 제품 추출 가정 (e.g., div class="product")
        products = soup.find_all('div', class_='product')
        if not products:
            # 단일 제품 가정
            products = [soup]
        
        for product in products:
            extracted_data = {'name': '', 'manufacturer': '', 'specs': {}}
            
            # 제품명 추출
            name_tag = product.find('h2', class_='product-name')
            if name_tag:
                extracted_data['name'] = name_tag.text.strip()
            
            # 제조사 추출
            manufacturer_tag = product.find('p', class_='manufacturer')
            if manufacturer_tag:
                extracted_data['manufacturer'] = manufacturer_tag.text.strip()
            
            # 스펙 추출
            spec_list = product.find_all('li', class_='spec-item')
            for spec in spec_list:
                match = re.match(r'(\w+)\s*:\s*([^\n]+)', spec.text, re.IGNORECASE)
                if match:
                    key = match.group(1).lower().strip()
                    value = match.group(2).strip()
                    extracted_data['specs'][key] = value
                    try:
                        conn = sqlite3.connect('database.db')
                        c = conn.cursor()
                        c.execute("INSERT OR IGNORE INTO spec_items (item_name) VALUES (?)", (key,))
                        conn.commit()
                    except sqlite3.Error as e:
                        print(f"SQLite error: {e}")
                        flash(f"데이터베이스 오류: {e}")
                    finally:
                        conn.close()
            
            if extracted_data['name']:  # 유효한 제품만 추가
                extracted_data_list.append(extracted_data)
        
        return extracted_data_list
    except Exception as e:
        print(f"Error parsing URL: {str(e)}")
        flash(f"URL 처리 중 오류 발생: {str(e)}")
        return []

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
    if request.method == 'POST':
        datasheet = form.datasheet.data
        product_url = form.product_url.data
        extracted_data = None
        if 'extract' in request.form:
            if datasheet:
                extracted_data = parse_datasheet(datasheet)
            elif product_url:
                extracted_data = parse_product_page(product_url)
            if extracted_data:
                if isinstance(extracted_data, list):
                    # 다중 제품
                    return render_template('add_equipment.html', form=form, extracted_list=extracted_data)
                else:
                    form.name.data = extracted_data['name']
                    form.manufacturer.data = extracted_data['manufacturer']
                    return render_template('add_equipment.html', form=form, extracted_specs=extracted_data['specs'])
        elif form.validate_on_submit():
            name = form.name.data
            manufacturer = form.manufacturer.data
            category = form.category.data
            upload_date = form.upload_date.data
            image = form.image.data if form.image.data else None
            image_url = ''
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
            c.execute("INSERT INTO equipment (name, manufacturer, category, specs, image, upload_date) VALUES (?, ?, ?, ?, ?, ?)",
                      (name, manufacturer, category, specs_str, image_url, upload_date))
            conn.commit()
            conn.close()
            return redirect(url_for('admin_dashboard'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT item_name FROM spec_items")
    spec_items = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('add_equipment.html', form=form, spec_items=spec_items, extracted_specs={}, extracted_list=[])

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

    form = AddEquipmentForm()
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