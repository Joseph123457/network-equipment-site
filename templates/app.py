from flask import Flask, render_template, request, redirect, url_for, session, flash
    from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
    from flask_wtf import FlaskForm
    from wtforms import StringField, PasswordField, SubmitField
    from wtforms.validators import DataRequired
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

    def init_db(env):
        conn = env.D1_DATABASE
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

    # Workers 환경에서 호출
    def init_app(app, env):
        init_db(env)

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

    def send_otp_to_telegram(chat_id, token, otp):
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {'chat_id': chat_id, 'text': f"Your OTP: {otp}"}
        response = requests.post(url, json=payload)
        print(f"Telegram API Response: {response.status_code} - {response.text}")
        return response

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/search', methods=['GET'])
    def search():
        query = request.args.get('q', '').lower()
        conn = app.env.D1_DATABASE
        c = conn.cursor()
        c.execute("SELECT * FROM equipment WHERE LOWER(name) LIKE ? OR LOWER(manufacturer) LIKE ? OR LOWER(specs) LIKE ?",
                  (f'%{query}%', f'%{query}%', f'%{query}%'))
        results = c.fetchall()
        conn.close()
        filtered_results = []
        for result in results:
            specs = eval(result[4]) if result[4] else {}
            if (query in result[1].lower() or query in result[2].lower() or
                any(query in str(value).lower() for value in specs.values())):
                filtered_results.append(result)
        return render_template('search.html', results=filtered_results)

    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        form = LoginForm()
        if form.validate_on_submit():
            conn = app.env.D1_DATABASE
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
        if request.method == 'POST':
            name = request.form['name']
            manufacturer = request.form['manufacturer']
            category = request.form['category']
            upload_date = request.form['upload_date']
            image = request.files['image'] if 'image' in request.files else None
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
            conn = app.env.D1_DATABASE
            c = conn.cursor()
            c.execute("INSERT INTO equipment (name, manufacturer, category, specs, image, upload_date) VALUES (?, ?, ?, ?, ?, ?)",
                      (name, manufacturer, category, specs_str, image_url, upload_date))
            conn.commit()
            conn.close()
            return redirect(url_for('admin_dashboard'))
        conn = app.env.D1_DATABASE
        c = conn.cursor()
        c.execute("SELECT item_name FROM spec_items")
        spec_items = [row[0] for row in c.fetchall()]
        conn.close()
        return render_template('add_equipment.html', spec_items=spec_items)

    @app.route('/admin/manage_specs', methods=['GET', 'POST'])
    @login_required
    def manage_specs():
        conn = app.env.D1_DATABASE
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
        conn = app.env.D1_DATABASE
        c = conn.cursor()
        c.execute("SELECT * FROM equipment WHERE id=?", (id,))
        equip = c.fetchone()
        conn.close()
        specs = eval(equip[4]) if equip[4] else {}
        return render_template('detail.html', equip=equip, specs=specs)

    def handler(env):
        app.env = env  # Workers 환경에서 D1 바인딩 저장
        init_app(app, env)
        return app

    if __name__ == '__main__':
        os.makedirs('static/uploads', exist_ok=True)
        app.run(debug=True)