# security.py
"""
보안 관련 유틸 모듈

- RSA 키 파일 로드/생성
- base64로 인코딩된 암호문 복호화
- 로그인 시도 콘솔 로그
"""

import os
import base64
import datetime
from typing import Tuple

from rsa_crypto import generate_keypair, decrypt


# 키 파일 경로 설정 (프로젝트 루트 기준)
KEY_DIR = "keys"
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "rsa_public.txt")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "rsa_private.txt")


def load_or_create_keys(bit_length: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    RSA 공개키/개인키를 파일에서 불러오거나, 없으면 새로 생성해서 저장.

    반환값:
        (public_key, private_key)
        public_key = (n, e)
        private_key = (n, d)
    """
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR, exist_ok=True)

    if os.path.exists(PUBLIC_KEY_PATH) and os.path.exists(PRIVATE_KEY_PATH):
        # 기존 키 로드
        with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
            n_str = f.readline().strip()
            e_str = f.readline().strip()

        with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
            n_str2 = f.readline().strip()
            d_str = f.readline().strip()

        # 혹시라도 n이 다르면 경고용 (실제론 거의 없겠지만)
        if n_str != n_str2:
            raise ValueError("공개키/개인키 파일의 n 값이 일치하지 않습니다.")

        n = int(n_str)
        e = int(e_str)
        d = int(d_str)
        public_key = (n, e)
        private_key = (n, d)
        print("[RSA] 기존 키 파일을 로드했습니다.")
        return public_key, private_key

    # 키 파일이 없으면 새로 생성
    print("[RSA] 키 파일이 없어 새로 생성합니다...")
    public_key, private_key = generate_keypair(bit_length=bit_length)
    n, e = public_key
    _, d = private_key

    with open(PUBLIC_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(str(n) + "\n")
        f.write(str(e) + "\n")

    with open(PRIVATE_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(str(n) + "\n")
        f.write(str(d) + "\n")

    print(f"[RSA] {bit_length}비트 키를 생성하고 파일에 저장했습니다.")
    return public_key, private_key


def decrypt_password_base64(cipher_b64: str, private_key: Tuple[int, int]) -> str:
    """
    base64 문자열로 전달된 RSA 암호문을 복호화하여 '평문 비밀번호'를 반환.

    절차:
        1) base64 디코딩 → bytes
        2) bytes → 정수로 변환
        3) rsa_crypto.decrypt(cipher_int, private_key) 호출
    """
    if not cipher_b64:
        raise ValueError("EMPTY_CIPHER")

    try:
        cipher_bytes = base64.b64decode(cipher_b64)
    except Exception as e:
        # base64 형식 자체가 깨진 경우
        raise ValueError("BASE64_DECODE_ERROR") from e

    if not cipher_bytes:
        raise ValueError("EMPTY_CIPHER_BYTES")

    cipher_int = int.from_bytes(cipher_bytes, byteorder="big")
    try:
        plaintext = decrypt(cipher_int, private_key)
    except Exception as e:
        # RSA 수학 연산 중 오류
        raise ValueError("RSA_DECRYPT_ERROR") from e

    return plaintext


def log_login_attempt(username: str, success: bool, reason: str) -> None:
    """
    로그인 시도 로그를 콘솔에 남김.
    나중에 파일/DB로 바꾸고 싶으면 이 함수 안만 수정하면 됨.

    예시 로그:
        [LOGIN] 2025-11-30T23:10:05 user='test' status=FAIL reason=WRONG_PASSWORD
    """
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    status = "SUCCESS" if success else "FAIL"
    user_str = username if username is not None else "(none)"
    print(f"[LOGIN] {timestamp} user={user_str!r} status={status} reason={reason}")
