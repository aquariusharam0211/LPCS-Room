# LPCS-Room

---

### 윤서진: 아니 준혁아 간단하게라도 HTML에 주석좀 달아줘 뭐라는지 모르겠음 



<rsa_crypto.py 제공 기능>(

+ generate_keypair(bit_length) -> RSA 키쌍 자동 생성
+ encrypt(plaintext, public_key) -> 문자열 → 암호문(정수)
+ decrypt(cipher_int, private_key) -> 암호문 → 문자열
)



<python rsa_crypto.py 실행>   <- 이거 lpcs 파일까지 cd로 들어가서 입력하면 돌아감(
+ 평문 입력: 여기에 512 비트 내로 입력하면 암호문 뜨고 성공 뜰거임, 512보다 높으면 강제로 에러남)



<rsa_crypto.py 현재 상태>  

+ RSA 기능만 만든 상태라 연결 직접해야함
+ 이거 말고는 건든거 없음
+ security.py도 만들어만 둔거임