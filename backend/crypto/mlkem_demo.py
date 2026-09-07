import oqs


def run_mlkem_demo():
    algorithm = "ML-KEM-768"

    with oqs.KeyEncapsulation(algorithm) as client:

        # Generate client's key pair
        public_key = client.generate_keypair()

        # Create another KEM instance to represent the other party
        with oqs.KeyEncapsulation(algorithm) as server:

            # Server uses client's public key
            ciphertext, server_secret = server.encap_secret(public_key)

            # Client recovers the shared secret
            client_secret = client.decap_secret(ciphertext)

    return {
        "algorithm": algorithm,
        "public_key_size": len(public_key),
        "ciphertext_size": len(ciphertext),
        "shared_secret_size": len(client_secret),
        "secrets_match": client_secret == server_secret
    }


if __name__ == "__main__":

    print("\n================================")
    print("       ML-KEM DEMONSTRATION")
    print("================================\n")

    result = run_mlkem_demo()

    for key, value in result.items():
        print(f"{key}: {value}")

    print("\n================================")

    if result["secrets_match"]:
        print("ML-KEM SUCCESS")
        print("Both parties generated the same shared secret.")
    else:
        print("ML-KEM FAILED")

    print("================================\n")