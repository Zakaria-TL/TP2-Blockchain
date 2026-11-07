import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from node import Node


def load_cert_and_pubkey(node_name):
    """دالة مساعدة لتحميل شهادة العقدة ومفتاح RSA العام الخاص بها"""
    cert_path = os.path.join("certs", f"{node_name}_cert.pem")
    with open(cert_path, "rb") as f:
        cert_pem = f.read()

    cert = x509.load_pem_x509_certificate(cert_pem)
    rsa_pub_key = cert.public_key()
    return cert_pem, rsa_pub_key


def main():
    print("=== 1. Initializing Nodes ===")
    alice = Node("alice")
    bob = Node("bob")
    carol = Node("carol")
    dave = Node("dave")
    peers = [bob, carol, dave]  # أليس ستتواصل مع هؤلاء

    # تحميل شهادة الـ CA
    with open(os.path.join("certs", "ca_cert.pem"), "rb") as f:
        ca_cert_pem = f.read()

    print("\n=== 2. Mutual Authentication (Alice <-> Bob) ===")
    alice_cert_pem, alice_rsa_pub = load_cert_and_pubkey("alice")
    bob_cert_pem, bob_rsa_pub = load_cert_and_pubkey("bob")

    # أليس تتحقق من شهادة بوب، وبوب يتحقق من شهادة أليس
    alice_trusts_bob = alice.verify_peer_certificate(bob_cert_pem, ca_cert_pem)
    bob_trusts_alice = bob.verify_peer_certificate(alice_cert_pem, ca_cert_pem)

    if alice_trusts_bob and bob_trusts_alice:
        print("[+] Certificates verified. Starting Challenge-Response...")

        # أليس تتحدى بوب
        challenge_for_bob = alice.generate_challenge()
        bob_response = bob.solve_challenge(challenge_for_bob)
        is_bob_legit = alice.verify_challenge_response(challenge_for_bob, bob_response, bob_rsa_pub)

        # بوب يتحدى أليس
        challenge_for_alice = bob.generate_challenge()
        alice_response = alice.solve_challenge(challenge_for_alice)
        is_alice_legit = bob.verify_challenge_response(challenge_for_alice, alice_response, alice_rsa_pub)

        if is_bob_legit and is_alice_legit:
            print("[+] Mutual Authentication SUCCESSFUL! Secure channel established.")
        else:
            print("[-] Mutual Authentication FAILED at challenge-response.")
            return

    print("\n=== 3. Transaction Gossiping ===")
    # أليس تنشئ معاملة لبوب وتمررها عبر الشبكة (Gossip)
    tx = alice.create_transaction(receiver="bob", amount=250.0, nonce=10)

    # نشر المعاملة لجميع الأقران
    alice.gossip_transaction(tx, peers)

    print("\n=== 4. Mempool Status ===")
    print(f"Bob's mempool size: {len(bob.mempool)} transaction(s)")
    print(f"Carol's mempool size: {len(carol.mempool)} transaction(s)")
    print(f"Dave's mempool size: {len(dave.mempool)} transaction(s)")


if __name__ == "__main__":
    main()