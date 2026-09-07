from analyzer.scanner import scan_code


code = """
import oqs

message = b"Hello"

with oqs.Signature("ML-DSA-65") as signer:

    public_key = signer.generate_keypair()

    signature = signer.sign(
        message,
        public_key
    )
"""

findings = scan_code(code)

print("\nCryptoAPI-Safe Results")
print("======================")

if not findings:
    print("No issues detected.")

else:
    for finding in findings:
        print("\n⚠️ Finding")
        print(f"Type: {finding['type']}")
        print(f"Algorithm: {finding['algorithm']}")
        print(f"API: {finding['api']}")
        print(f"Severity: {finding['severity']}")
        print(f"Line: {finding['line']}")
        print(f"Message: {finding['message']}")
        print(f"Recommendation: {finding['recommendation']}")