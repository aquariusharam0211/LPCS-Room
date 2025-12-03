# app.py
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import pymysql
import webbrowser
import threading
import os
import hashlib
import bcrypt
import datetime

from security import load_or_create_keys, decrypt_password_base64, log_login_attempt

app = Flask(__name__)
CORS(app)

# ============================
#        로그 저장 함수
# ============================
def log_event(message):
    """log.txt 파일에 로그 저장"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}\n"
    with open("log.txt", "a", encoding="utf-8") as f:
        f.write(line)

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

@app.route('/public-key', methods=['GET'])
def get_public_key():
    n, e = public_key
    return jsonify({
        "n": str(n),  # modulus
        "e": str(e)   # 공개 지수
    })

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
        log_event(f"REGISTER FAIL: username={username}, reason=decrypt_fail")
        return jsonify({'message': '비밀번호 복호화 실패', 'error': str(e)}), 400

    # SHA256 → bcrypt
    sha_pw = hashlib.sha256(plain_pw.encode()).digest()
    hashed_pw = bcrypt.hashpw(sha_pw, bcrypt.gensalt()).decode()

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, hashed_pw)
    )
    db.commit()

    log_login_attempt(username, True, "REGISTER_SUCCESS")
    log_event(f"REGISTER SUCCESS: username={username}")

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
        log_event(f"LOGIN FAIL: username={username}, reason=user_not_found")
        return jsonify({'message': '아이디 또는 비밀번호가 틀렸습니다'}), 400

    stored_hash = result[0]

    # RSA 복호화
    try:
        plain_pw = decrypt_password_base64(cipher_b64, private_key)
    except ValueError as e:
        log_login_attempt(username, False, str(e))
        log_event(f"LOGIN FAIL: username={username}, reason=decrypt_fail")
        return jsonify({'message': '비밀번호 복호화 실패', 'error': str(e)}), 400

    sha_pw = hashlib.sha256(plain_pw.encode()).digest()

    if bcrypt.checkpw(sha_pw, stored_hash.encode()):
        log_login_attempt(username, True, "LOGIN_SUCCESS")
        log_event(f"LOGIN SUCCESS: username={username}")
        return jsonify({'message': '로그인 성공!'}), 200
    else:
        log_login_attempt(username, False, "WRONG_PASSWORD")
        log_event(f"LOGIN FAIL: username={username}, reason=wrong_password")
        return jsonify({'message': '아이디 또는 비밀번호가 틀렸습니다'}), 400

# ============================
#     브라우저 자동 실행
# ============================
def open_browser():
    webbrowser.open("http://127.0.0.1:5000/")

if __name__ == '__main__':
    threading.Timer(1.0, open_browser).start()
    app.run(debug=True, use_reloader=False)
