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




<추가된 것>

1.RSA 암호화 → Flask 로그인 로직에 실제 연결됨

+ 이제 클라이언트는 pw_cipher(base64 인코딩된 RSA 암호문)을 보내고

+ 서버(app.py)는 decrypt_password_base64()로 복호화해서 DB와 비교함

+ 즉, 평문 로그인 방식 → 암호문 기반 로그인 방식으로 변경됨

2./login 구조 전체 업그레이드됨

+ 평문 pw 받던 구조 → RSA 암호문 받는 구조로 완전 변경

+ 실패 사유(reason)를 JSON으로 반환

+ 콘솔에 로그인 시도 기록 출력 (log_login_attempt)

+ 오류 분기 명확해짐 (MISSING_FIELD / BASE64_ERROR / RSA_DECRYPT_ERROR / WRONG_PASSWORD 등)

3.security.py 개념적 완성

+ base64 decode

+ RSA 복호화 래퍼 함수

+ 로그인 기록 함수(log_login_attempt)

+ (해시 기능은 아직 없음 → 이후 단계에서 추가)

4.서버가 RSA 키를 직접 생성하고 내부에서 유지

+ PUBLIC_KEY / PRIVATE_KEY 실행 시 자동 생성

+ 공개키는 향후 프론트엔드에 전달 가능하도록 구조 설계됨




<다음에 추가할 내용>

1.비밀번호 해싱(bcrypt/argon2)

+ RSA는 전송 중(네트워크 상) 보호

+ 해시는 DB 저장용 보호

+ 현재 DB에 평문 저장 중 → 다음 보완 단계에서 필수 수정

2.회원가입(register)에도 RSA 적용하기

+ 현재는 로그인만 RSA 적용됨

+ 회원가입도 동일하게 암호문으로 전송하도록 변경 예정

3./public-key API 추가

+ HTML이 서버로부터 자동으로 공개키(n, e)를 받아올 수 있게 만들기

+ 현재는 수동 테스트 단계

4.로그 더 체계화(Log 파일 저장)

+ 지금은 콘솔 출력만 되는 상태

+ 다음 업데이트에서는 log.txt 파일에 저장해서 공격 분석(AI를 활용한 실험)용 데이터 축적

5.키 교체(Key Rotation) 구조 설계

+ 지금은 서버 실행 시마다 새로 키 생성

+ 실전 보안 단계에서 일정 주기로 키 재생성하는 로직 추가 예정



###지금 ㅈ1ㄴ 정신 몽롱해서 졸려서 오류 있으면 적어줘 11/30 일요일에 이어서 해볼게 현재 4시30분 난 자러간다ㅏㅏㅏㅏㅏ
참고로 내가 DB 서버 프로그램없어서 못돌려서 네가 확인좀해줘