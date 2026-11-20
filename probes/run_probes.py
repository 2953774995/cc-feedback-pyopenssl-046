#!/usr/bin/env python3
"""验收探针：X.509 证书批量体检（6 条契约）。证书现场签发，离线校验。"""
import sys, time, datetime
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def audit():
    from OpenSSL.audit import inspect_certs
    return inspect_certs

def make_cert(bits=2048, days=365, cn="a.example.com", expired=False, sha1=False):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    now = datetime.datetime(2026, 11, 20)
    start = now - datetime.timedelta(days=800 if expired else 10)
    end = now - datetime.timedelta(days=1 if expired else days)
    alg = hashes.SHA1() if sha1 else hashes.SHA256()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(start).not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, alg))
    return cert.public_bytes(serialization.Encoding.PEM)

@probe("P01 批量入口与正常证书")
def p01():
    fn = audit(); out = fn([make_cert()])
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for k in ("index", "ok", "reason", "subject", "issuer", "key_bits", "sig_alg", "san", "issues"):
        assert k in item, f"item 缺字段 {k}"
    assert item["ok"] and item["reason"] == "ok", f"正常证书应 ok，实际 {item['reason']}"
    assert item["key_bits"] == 2048 and "a.example.com" in " ".join(item["san"]), "应抽出位数与 SAN"

@probe("P02 过期证书")
def p02():
    fn = audit(); item = fn([make_cert(expired=True)], now="2026-11-20T00:00:00Z").items[0]
    assert item["reason"] == "expired", f"应为 expired，实际 {item['reason']}"
    assert not item["ok"]

@probe("P03 弱密钥长度")
def p03():
    fn = audit(); item = fn([make_cert(bits=1024)], min_key_bits=2048).items[0]
    assert "weak_key" in item["issues"], f"应报 weak_key，实际 {item['issues']}"
    assert not item["ok"]

@probe("P04 SHA1 签名")
def p04():
    fn = audit()
    try:
        item = fn([make_cert(sha1=True)]).items[0]
    except Exception as exc:
        raise AssertionError(f"签发 SHA1 证书失败：{exc}")
    assert "weak_signature" in item["issues"], f"应报 weak_signature，实际 {item['issues']}"

@probe("P05 坏输入隔离")
def p05():
    fn = audit(); out = fn([b"not a cert", make_cert()])
    assert out.items[0]["reason"] == "malformed", f"应为 malformed，实际 {out.items[0]['reason']}"
    assert out.items[1]["ok"], "坏输入之后应继续"

@probe("P06 统计、空输入与批量性能")
def p06():
    fn = audit(); good, bad = make_cert(), make_cert(expired=True)
    out = fn([good, bad], now="2026-11-20T00:00:00Z")
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 1, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("expired") == 1, f"by_reason 不对：{st['by_reason']}"
    empty = fn([]); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    certs = [good] * 120
    t0 = time.perf_counter(); out2 = fn(certs); cost = time.perf_counter() - t0
    assert len(out2.items) == 120 and cost < 3.0, f"120 张耗时 {cost:.2f}s 超过 3s"

def main():
    print("=" * 60); print("验收探针：X.509 证书批量体检（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
