from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import pymysql
import webbrowser
import threading

app = Flask(__name__)
CORS(app)  # CORS 허용 (index.html에서 index4.html 이동 가능)

# MySQL 연결
db = pymysql.connect(
    host='127.0.0.1',
    user='root',
    password='jeeto3000@',
    database='code',
    charset='utf8mb4'
)
cursor = db.cursor()

# HTML 라우트
@app.route('/')
def login_page():
    return render_template('index.html')

@app.route('/signup')
def signup_page():
    return render_template('index4.html')

# 회원가입 POST
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('id')
    password = data.get('pw')

    if not username or not password:
        return jsonify({'message': '아이디와 비밀번호를 모두 입력하세요'}), 400

    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    if cursor.fetchone():
        return jsonify({'message': '이미 존재하는 아이디입니다'}), 400

    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
    db.commit()
    return jsonify({'message': '회원가입 완료!'}), 200

# 로그인 POST
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('id')
    password = data.get('pw')

    if not username or not password:
        return jsonify({'message': '아이디와 비밀번호를 모두 입력하세요'}), 400

    cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
    user = cursor.fetchone()
    if user:
        return jsonify({'message': '로그인 성공!'}), 200
    else:
        return jsonify({'message': '아이디 또는 비밀번호가 틀렸습니다'}), 400

# 브라우저 자동 실행 (서버 한 번만 실행)
def open_browser():
    webbrowser.open("http://127.0.0.1:5000/")

if __name__ == '__main__':
    # debug=True 유지, but reloader 끄기
    threading.Timer(1.0, open_browser).start()
    app.run(debug=True, use_reloader=False)
