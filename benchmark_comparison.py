import time
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes


def run_benchmark():
    message = b"Blockchain consensus test transaction payload."
    iterations = 1000

    print(f"[*] Running benchmark over {iterations} messages...\n")

    # ==========================================
    # 1. ECDSA (secp256k1) Benchmark
    # ==========================================
    ecdsa_private_key = ec.generate_private_key(ec.SECP256K1())
    ecdsa_public_key = ecdsa_private_key.public_key()

    # قياس وقت التوقيع (Sign)
    start_time = time.time()
    for _ in range(iterations):
        ecdsa_signature = ecdsa_private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    ecdsa_sign_duration = time.time() - start_time

    # قياس وقت التحقق (Verify)
    start_time = time.time()
    for _ in range(iterations):
        ecdsa_public_key.verify(
            ecdsa_signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
    ecdsa_verify_duration = time.time() - start_time

    ecdsa_sig_size = len(ecdsa_signature)

    # ==========================================
    # 2. Ed25519 Benchmark
    # ==========================================
    ed_private_key = ed25519.Ed25519PrivateKey.generate()
    ed_public_key = ed_private_key.public_key()

    # قياس وقت التوقيع (Sign)
    start_time = time.time()
    for _ in range(iterations):
        ed_signature = ed_private_key.sign(message)
    ed_sign_duration = time.time() - start_time

    # قياس وقت التحقق (Verify)
    start_time = time.time()
    for _ in range(iterations):
        ed_public_key.verify(ed_signature, message)
    ed_verify_duration = time.time() - start_time

    ed_sig_size = len(ed_signature)

    # ==========================================
    # طباعة النتائج بشكل مقارن
    # ==========================================
    print("=" * 65)
    print(f"{'Algorithm':<15} | {'Sig Size (Bytes)':<18} | {'Sign 1000x (s)':<15} | {'Verify 1000x (s)'}")
    print("-" * 65)
    print(
        f"{'ECDSA (secp256k1)':<15} | {ecdsa_sig_size:<18} | {ecdsa_sign_duration:<15.4f} | {ecdsa_verify_duration:.4f}")
    print(f"{'Ed25519':<15} | {ed_sig_size:<18} | {ed_sign_duration:<15.4f} | {ed_verify_duration:.4f}")
    print("=" * 65)


if __name__ == "__main__":
    run_benchmark()