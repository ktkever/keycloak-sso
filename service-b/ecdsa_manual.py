"""ECDSA(P-256) 서명 검증을 수업 수식 그대로 직접 구현한 모듈

수업 내용과의 대응
- 모듈러 역원: 확장 유클리드 알고리즘 (egcd, mod_inverse)
- 소수체 타원곡선 E_p(a, b): y^2 = x^3 + ax + b (mod p)
- 두 점 덧셈 / 2배 연산: 기울기 lambda로 좌표 계산 (point_add)
- 스칼라 곱 kP: double-and-add (scalar_mult)
- ECDSA 검증: w = s^-1, u1 = H(m)w, u2 = rw, X = u1*G + u2*Q, x(X) mod n == r ?

외부 암호 라이브러리 없이 hashlib(SHA-256)만 사용한다.
"""
import base64
import hashlib

# ── NIST P-256 (secp256r1) 곡선 파라미터 ─────────────────────────────
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF  # 소수 p
A = P - 3                                                              # a = -3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)                                                                      # 생성점 G
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # G의 위수 n

O = None  # 무한원점 (덧셈의 항등원)


# ── 정수론: 확장 유클리드 알고리즘과 모듈러 역원 ─────────────────────
def egcd(a, b):
    """ax + by = gcd(a, b)를 만족하는 (gcd, x, y) 반환"""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("역원이 존재하지 않습니다")
    return x % m


# ── 타원곡선 연산 ───────────────────────────────────────────────────
def is_on_curve(pt):
    if pt is O:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_neg(pt):
    if pt is O:
        return O
    x, y = pt
    return (x, (-y) % P)


def point_add(p1, p2):
    if p1 is O:
        return p2
    if p2 is O:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:  # P + (-P) = O
        return O
    if p1 == p2:  # 2배 연산: lambda = (3x^2 + a) / 2y
        lam = (3 * x1 * x1 + A) * mod_inverse(2 * y1, P) % P
    else:         # 두 점 덧셈: lambda = (y2 - y1) / (x2 - x1)
        lam = (y2 - y1) * mod_inverse(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, pt):
    """k * pt 를 double-and-add로 계산"""
    result, addend = O, pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# ── ECDSA 검증 ──────────────────────────────────────────────────────
def ecdsa_verify(message: bytes, r: int, s: int, Q):
    """수업 수식 그대로 검증하고, 중간 계산값을 모두 반환"""
    steps = {"r": r, "s": s}
    if not (1 <= r < N and 1 <= s < N):
        steps["valid"] = False
        steps["reason"] = "r, s가 [1, n-1] 범위를 벗어남"
        return steps
    if Q is O or not is_on_curve(Q):
        steps["valid"] = False
        steps["reason"] = "공개키 Q가 곡선 위의 점이 아님"
        return steps

    e = int.from_bytes(hashlib.sha256(message).digest(), "big")  # H(m)
    w = mod_inverse(s, N)          # w = s^-1 mod n
    u1 = e * w % N                 # u1 = H(m) * s^-1 mod n
    u2 = r * w % N                 # u2 = r * s^-1 mod n
    X = point_add(scalar_mult(u1, G), scalar_mult(u2, Q))  # X = u1*G + u2*Q

    steps.update(e=e, w=w, u1=u1, u2=u2)
    if X is O:
        steps.update(valid=False, reason="X가 무한원점")
        return steps
    v = X[0] % N
    steps.update(X=X, v=v, valid=(v == r))
    return steps


# ── JWT(ES256) 연결부 ───────────────────────────────────────────────
def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def verify_jwt_es256(token: str, jwk: dict):
    """JWT 서명 = base64url(r || s), 각 32바이트 / 서명 대상 m = 'header.payload'"""
    header_b64, payload_b64, sig_b64 = token.split(".")
    sig = b64url_decode(sig_b64)
    if len(sig) != 64:
        return {"valid": False, "reason": f"서명 길이가 64바이트가 아님({len(sig)})"}
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    Q = (int.from_bytes(b64url_decode(jwk["x"]), "big"),
         int.from_bytes(b64url_decode(jwk["y"]), "big"))
    message = f"{header_b64}.{payload_b64}".encode("ascii")
    steps = ecdsa_verify(message, r, s, Q)
    steps["Q"] = Q
    steps["message_preview"] = message[:60].decode() + "…"
    return steps
