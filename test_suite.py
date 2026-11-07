from node import Node

# 1. إنشاء العقدتين Alice و Bob
alice = Node("alice")
bob = Node("bob")

print("--- Test 1: Normal Valid Transaction ---")
# أليس ترسل معاملة برقم Nonce = 1
tx1 = alice.create_transaction(receiver="bob", amount=100.0, nonce=1)
# بوب يستقبل المعاملة ويتحقق منها باستخدام مفتاح أليس العام
bob.receive_transaction(tx1, alice.public_key)

print("\n--- Test 2: Replay Attack (Duplicate Nonce) ---")
# محاولة إعادة إرسال نفس المعاملة أو نفس الـ Nonce (nonce=1)
bob.receive_transaction(tx1, alice.public_key)

print("\n--- Test 3: Tampered Transaction ---")
# إنشاء معاملة جديدة ثم التلاعب بمبلغها بعد التوقيع
tx2 = alice.create_transaction(receiver="bob", amount=50.0, nonce=2)
tx2.amount = 9999.0  # تعديل خبيث للمبلغ دون إعادة التوقيع!
bob.receive_transaction(tx2, alice.public_key)