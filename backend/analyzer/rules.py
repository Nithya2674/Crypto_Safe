PQC_RULES = {

    "ML-KEM": {
        "KeyEncapsulation": {
            "generate_keypair": {
                "description": "Generates an ML-KEM public/private key pair.",
                "severity": "INFO"
            },

            "encap_secret": {
                "required_key": "public_key",
                "description": "Encapsulation must use the recipient's public key.",
                "severity": "HIGH"
            },

            "decap_secret": {
                "required_key": "secret_key",
                "description": "Decapsulation requires the recipient's secret key.",
                "severity": "HIGH"
            }
        }
    },

    "ML-DSA": {
        "Signature": {
            "generate_keypair": {
                "description": "Generates an ML-DSA signing key pair.",
                "severity": "INFO"
            },

            "sign": {
                "required_key": "secret_key",
                "description": "Signing requires the private/signing key.",
                "severity": "HIGH"
            },

            "verify": {
                "required_key": "public_key",
                "description": "Verification requires the public verification key.",
                "severity": "HIGH"
            }
        }
    }
}