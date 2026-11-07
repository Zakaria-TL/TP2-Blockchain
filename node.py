import os
import time
import datetime
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from transaction import Transaction


class Node:
    def __init__(self, node_name):
        self.node_name = node_name.lower()
        self.mempool = []  # ذاكرة المعاملات المؤقتة
        self.seen_nonces = {}  # للوقاية من Replay Protection (مفتاح: المرسل، قيمة: مجموعة الـ nonces المستخدمة)

        # تحميل مفتاح ECDSA الخاص بالعقدة
        self.private_key = self.load_ecdsa_private_key()
        # تحميل المفتاح العام للمرسل (للاختبار والتحقق)
        self.public_key = self.private_key.public_key()

    def verify_peer_certificate(self, peer_cert_pem, ca_cert_pem):
        """التحقق من شهادة العقدة المقابلة باستخدام شهادة الـ CA"""
        try:
            peer_cert = x509.load_pem_x509_certificate(peer_cert_pem)
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

            # 1. التحقق من صلاحية التواريخ
            now = datetime.datetime.utcnow()
            if not (peer_cert.not_valid_before <= now <= peer_cert.not_valid_after):
                print(f"[-] [{self.node_name}] Peer certificate is expired or not yet valid.")
                return False

            # 2. التحقق من أن الشهادة موقعة من الـ CA الحقيقي
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                peer_cert.signature,
                peer_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                peer_cert.signature_hash_algorithm,
            )
            print(f"[+] [{self.node_name}] Peer certificate verified successfully.")
            return True
        except Exception as e:
            print(f"[-] [{self.node_name}] Certificate verification failed: {e}")
            return False

    def generate_challenge(self):
        """توليد تحدي عشوائي (تشفير غير متماثل أو توقيع)"""
        return os.urandom(32)

    def solve_challenge(self, challenge_bytes):
        """توقيع التحدي باستخدام مفتاح RSA الخاص بإثبات الهوية (الموروث من TP1)"""
        priv_path = os.path.join("certs", f"{self.node_name}_key.pem")
        with open(priv_path, "rb") as f:
            rsa_private_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = rsa_private_key.sign(
            challenge_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_challenge_response(self, challenge_bytes, response_signature, peer_rsa_public_key):
        """التحقق من استجابة التحدي الخاصة بالطرف الآخر"""
        try:
            peer_rsa_public_key.verify(
                response_signature,
                challenge_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def gossip_transaction(self, tx, peers):
        """نشر المعاملة الصحيحة إلى باقي العقد في الشبكة (Gossip Protocol)"""
        print(f"[*] [{self.node_name}] Gossiping transaction to peers...")
        for peer in peers:
            peer.receive_transaction(tx, self.public_key)

    def load_ecdsa_private_key(self):
        """تحميل المفتاح الخاص من مجلد certs"""
        priv_path = os.path.join("certs", f"{self.node_name}_ecdsa_key.pem")
        with open(priv_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None
            )

    def create_transaction(self, receiver, amount, nonce):
        """إنشاء وتوقيع معاملة جديدة مرسلة من هذه العقدة"""
        tx = Transaction(
            sender=self.node_name,
            receiver=receiver,
            amount=amount,
            nonce=nonce
        )
        tx.sign(self.private_key)
        return tx

    def receive_transaction(self, tx, sender_public_key):
        """استقبال معاملة، التحقق من توقيعها، وقتها، وعدم تكرار الـ Nonce"""

        # 1. التحقق من صحة التوقيع الرياضي
        if not tx.verify(sender_public_key):
            print(f"[-] [{self.node_name}] REJECTED: Invalid signature for transaction from {tx.sender}")
            return False

        # 2. Replay Protection: التحقق من نطاق الزمن (Timestamp) - ألا تكون أقدم من 60 ثانية
        current_time = time.time()
        if abs(current_time - tx.timestamp) > 60:
            print(f"[-] [{self.node_name}] REJECTED: Timestamp out of bounds for transaction from {tx.sender}")
            return False

        # 3. Replay Protection: التحقق من عدم تكرار الـ Nonce لنفس المرسل
        if tx.sender not in self.seen_nonces:
            self.seen_nonces[tx.sender] = set()

        if tx.nonce in self.seen_nonces[tx.sender]:
            print(
                f"[-] [{self.node_name}] REJECTED: Replay attack detected! Nonce {tx.nonce} already used by {tx.sender}")
            return False

        # إذا اجتازت كل الشروط: قبول المعاملة وحفظ الـ Nonce وإضافتها للـ Mempool
        self.seen_nonces[tx.sender].add(tx.nonce)
        self.mempool.append(tx)
        print(
            f"[+] [{self.node_name}] ACCEPTED: Valid transaction from {tx.sender} to {tx.receiver} (Amount: {tx.amount})")
        return True