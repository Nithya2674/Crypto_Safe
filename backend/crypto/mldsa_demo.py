import oqs


def run_mldsa_demo():
    algorithm = "ML-DSA-65"
    message = b"CryptoAPI-Safe demonstration"

    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()

        signature = signer.sign(message)

        valid = signer.verify(
            message,
            signature,
            public_key
        )

        modified_message = b"Modified message"

        modified_valid = signer.verify(
            modified_message,
            signature,
            public_key
        )

    return {
        "algorithm": algorithm,
        "public_key_size": len(public_key),
        "signature_size": len(signature),
        "original_message_valid": valid,
        "modified_message_valid": modified_valid,
    }


if __name__ == "__main__":
    result = run_mldsa_demo()

    for key, value in result.items():
        print(f"{key}: {value}")