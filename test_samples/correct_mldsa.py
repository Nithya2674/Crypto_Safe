import oqs

message = b"Hello PQC"

with oqs.Signature("ML-DSA-65") as signer:

    public_key = signer.generate_keypair()

    signature = signer.sign(message)

    result = signer.verify(
        message,
        signature,
        public_key
    )