from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import pymysql
import webbrowser
import threading

from security import load_or_create_keys, decrypt_password_base64, log_login_attempt

app = Flask(__name__)
CORS(app)  # CORS 허용

# ==================== RSA 키 로딩 ====================

# 서버 시작 시 2048비트 키를 파일에서 로드하거나, 없으면 생성
PUBLIC_KEY, PRIVATE_KEY = load_or_create_keys(bit_length=2048)


# ==================== MySQL 연결 ====================

db = pymysql.connect(
    host='127.0.0.1',
    user='root',
    password='jeeto3000@',
    database='code',
    charset='utf8mb4'
)
cursor = db.cursor()


# ==================== HTML 라우트 ====================

@app.route('/')
def login_page():
    # templates 폴더 아래에 index.html 이 있어야 합니다.
    return render_template('index.html')


@app.route('/signup')
def signup_page():
    # templates 폴더 아래에 index4.html 이 있어야 합니다.
    return render_template('index4.html')


# ==================== RSA 공개키 제공 엔드포인트 ====================

@app.route('/public-key', methods=['GET'])
def get_public_key():
    """
    클라이언트(프론트엔드)가 RSA 암호화를 하기 위해 공개키를 가져가는 엔드포인트.

    응답 예:
    {
        "alg": "RSA",
        "key_size": 2048,
        "n": "<10진수 문자열>",
        "e": 65537
    }
    """
    n, e = PUBLIC_KEY
    return jsonify({
        "alg": "RSA",
        "key_size": 2048,
        "n": str(n),   # 큰 정수이므로 문자열로 전달
        "e": e
    })


# ==================== 회원가입 (아직 평문 버전) ====================

@app.route('/register', methods=['POST'])
def register():
    """
    1차 버전: 회원가입은 아직 평문 비밀번호를 그대로 사용.
    - 요청 JSON: { "id": "user", "pw": "plain_password" }
    - 보완 단계에서 RSA/해시 적용 예정.
    """
    data = request.get_json()
    username = data.get('id')
    password = data.get('pw')

    if not username or not password:
        return jsonify({'message': '아이디와 비밀번호를 모두 입력하세요'}), 400

    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    if cursor.fetchone():
        return jsonify({'message': '이미 존재하는 아이디입니다'}), 400

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, password)
    )
    db.commit()
    return jsonify({'message': '회원가입 완료!'}), 200


# ==================== 로그인 (RSA + base64 + 콘솔 로그) ====================

@app.route('/login', methods=['POST'])
def login():
    """
    로그인은 RSA + base64를 사용하는 버전.

    기대하는 요청 JSON 형식:
        {
            "id": "user123",
            "pw_cipher": "<base64로 인코딩된 RSA 암호문>"
        }

    처리 순서:
        1) JSON 파싱
        2) pw_cipher base64 디코딩 + RSA 복호화 → 평문 비밀번호
        3) DB에서 username, password로 확인
        4) 결과에 따라 로그인 성공/실패 + 콘솔 로그
    """
    data = request.get_json() or {}
    username = data.get('id')
    pw_cipher_b64 = data.get('pw_cipher')

    # 입력값 체크
    if not username or not pw_cipher_b64:
        log_login_attempt(username, False, "MISSING_FIELD")
        return jsonify({'message': '아이디와 암호문을 모두 입력하세요', 'reason': 'MISSING_FIELD'}), 400

    # RSA + base64 복호화
    try:
        plain_password = decrypt_password_base64(pw_cipher_b64, PRIVATE_KEY)
    except ValueError as e:
        reason = str(e)  # 예: "BASE64_DECODE_ERROR", "RSA_DECRYPT_ERROR"
        log_login_attempt(username, False, reason)
        return jsonify({
            'message': '암호화/복호화 과정에서 오류가 발생했습니다.',
            'reason': reason
        }), 400

    # DB에서 사용자 조회 (현재는 평문 비밀번호를 그대로 사용)
    cursor.execute(
        "SELECT * FROM users WHERE username=%s AND password=%s",
        (username, plain_password)
    )
    user = cursor.fetchone()

    if user:
        log_login_attempt(username, True, "OK")
        return jsonify({'message': '로그인 성공!', 'reason': 'OK'}), 200
    else:
        log_login_attempt(username, False, "WRONG_PASSWORD")
        return jsonify({'message': '아이디 또는 비밀번호가 틀렸습니다', 'reason': 'WRONG_PASSWORD'}), 400


# ==================== 브라우저 자동 실행 ====================

def open_browser():
    webbrowser.open("http://127.0.0.1:5000/")


if __name__ == '__main__':
    # debug=True 유지, but reloader 끄기
    threading.Timer(1.0, open_browser).start()
    app.run(debug=True, use_reloader=False)
