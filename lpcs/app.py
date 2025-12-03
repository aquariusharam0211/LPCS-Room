# app.py
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import pymysql
import webbrowser
import threading
import os
import hashlib
import bcrypt

from security import load_or_create_keys, decrypt_password_base64, log_login_attempt

app = Flask(__name__)
CORS(app)

# ============================
#       DB 연결
# ============================
db = pymysql.connect(
    host='127.0.0.1',
    user='root',
    password='jeeto3000@',
    database='code',
    charset='utf8mb4'
)
cursor = db.cursor()

# ============================
#       RSA 키 준비
# ============================
public_key, private_key = load_or_create_keys(bit_length=1024)

# ============================
#       HTML 페이지
# ============================
@app.route('/')
def login_page():
    return render_template('index.html')

@app.route('/signup')
def signup_page():
    return render_template('index4.html')

# ============================
#        회원가입
# ============================
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('id')
    cipher_b64 = data.get('pw')

    if not username or not cipher_b64:
        return jsonify({'message': '아이디와 비밀번호를 모두 입력하세요'}), 400

    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    if cursor.fetchone():
        return jsonify({'message': '이미 존재하는 아이디입니다'}), 400

    # RSA 복호화
    try:
        plain_pw = decrypt_password_base64(cipher_b64, private_key)
    except ValueError as e:
        log_login_attempt(username, False, str(e))
        return jsonify({'message': '비밀번호 복호화 실패', 'error': str(e)}), 400

    # SHA256 → bcrypt 적용
    sha_pw = hashlib.sha256(plain_pw.encode()).digest()  # 32바이트
    hashed_pw = bcrypt.hashpw(sha_pw, bcrypt.gensalt()).decode()

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, hashed_pw)
    )
    db.commit()

    log_login_attempt(username, True, "REGISTER_SUCCESS")
    return jsonify({'message': '회원가입 완료!'}), 200

# ============================
#           로그인
# ============================
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('id')
    cipher_b64 = data.get('pw')

    if not username or not cipher_b64:
        return jsonify({'message': '아이디와 비밀번호를 모두 입력하세요'}), 400

    cursor.execute("SELECT password FROM users WHERE username=%s", (username,))
    result = cursor.fetchone()
    if not result:
        log_login_attempt(username, False, "USER_NOT_FOUND")
        return jsonify({'message': '아이디 또는 비밀번호가 틀렸습니다'}), 400

    stored_hash = result[0]

    try:
        plain_pw = decrypt_password_base64(cipher_b64, private_key)
    except ValueError as e:
        log_login_attempt(username, False, str(e))
        return jsonify({'message': '비밀번호 복호화 실패', 'error': str(e)}), 400

    sha_pw = hashlib.sha256(plain_pw.encode()).digest()  # 32바이트

    if bcrypt.checkpw(sha_pw, stored_hash.encode()):
        log_login_attempt(username, True, "LOGIN_SUCCESS")
        return jsonify({'message': '로그인 성공!'}), 200
    else:
        log_login_attempt(username, False, "WRONG_PASSWORD")
        return jsonify({'message': '아이디 또는 비밀번호가 틀렸습니다'}), 400

# ============================
#     브라우저 자동 실행
# ============================
def open_browser():
    webbrowser.open("http://127.0.0.1:5000/")

if __name__ == '__main__':
    threading.Timer(1.0, open_browser).start()
    app.run(debug=True, use_reloader=False)
