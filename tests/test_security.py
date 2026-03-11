from app.core.security import hash_password, verify_password


def test_password_hash_roundtrip():
    hashed = hash_password('P@ssw0rd!')
    assert hashed.startswith('pbkdf2_sha256$')
    assert verify_password('P@ssw0rd!', hashed)
    assert not verify_password('wrong', hashed)
