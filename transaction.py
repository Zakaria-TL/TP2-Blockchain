import time
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class Transaction:
    def __init__(self, sender, receiver, amount, nonce):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.nonce = nonce
        self.timestamp = time.time()
        self.signature = None  # التوقيع سيكون بصيغة نصية (Base64)

    def to_dict(self):
        """تحويل حقول المعاملة إلى قاموس (بدون التوقيع) لضمان ثبات الـ Hash"""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "nonce": self.nonce,
            "timestamp": self.timestamp
        }

    def get_signable_bytes(self):
        """ترتيب الحقول بصيغة JSON وثابتة لتوليد الـ Hash بدقة"""
        return json.dumps(self.to_dict(), sort_keys=True).encode('utf-8')

    def sign(self, private_key):
        """توقيع المعاملة باستخدام مفتاح ECDSA الخاص (secp256k1)"""
        # 1. حساب SHA-256 لبيانات المعاملة
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.get_signable_bytes())
        message_hash = digest.finalize()

        # 2. التوقيع باستخدام ECDSA
        sig = private_key.sign(
            message_hash,
            ec.ECDSA(hashes.SHA256())
        )

        # 3. ترميز التوقيع إلى Base64 لنقله بسهولة عبر الشبكة
        self.signature = base64.b64encode(sig).decode('utf-8')

    def verify(self, public_key):
        """التحقق من صحة التوقيع باستخدام المفتاح العام للمرسل"""
        if not self.signature:
            return False

        try:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self.get_signable_bytes())
            message_hash = digest.finalize()

            decoded_sig = base64.b64decode(self.signature)

            # التحقق من صحة التوقيع الرياضي
            public_key.verify(
                decoded_sig,
                message_hash,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            print(f"[-] Signature verification failed: {e}")
            return False