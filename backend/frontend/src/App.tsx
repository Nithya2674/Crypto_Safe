import { useState, useEffect } from "react";
import "./index.css";
import DiffViewer from "./components/DiffViewer";

interface Scenario {
  name: string;
  category: string;
  code: string;
}

const SCENARIOS: Scenario[] = [
  {
    name: "1. ML-DSA Key Confusion (Public Key in Sign)",
    category: "Key Management",
    code: `import oqs

message = b"Confidential Contract v1"

with oqs.Signature("ML-DSA-65") as signer:
    public_key = signer.generate_keypair()

    # Flaw: Passing public key to sign()
    signature = signer.sign(
        message,
        public_key
    )`
  },
  {
    name: "2. Legacy RSA-2048 (Harvest Now, Decrypt Later)",
    category: "Quantum Vulnerability",
    code: `from cryptography.hazmat.primitives.asymmetric import rsa

# Flaw: RSA-2048 is completely vulnerable to Shor's Algorithm
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()`
  },
  {
    name: "3. Weak Randomness (Predictable PRNG for Seed)",
    category: "Randomness & Entropy",
    code: `import random

# Flaw: random.randint uses Mersenne Twister (predictable after 624 outputs)
seed_int = random.randint(100000, 999999)
pqc_seed = str(seed_int).encode()`
  },
  {
    name: "4. Ignored Signature Verification",
    category: "Verification",
    code: `import oqs

with oqs.Signature("ML-DSA-65") as signer:
    pk = signer.generate_keypair()
    sig = signer.sign(b"Transaction #1042")

    # Flaw: Bare verify() statement; boolean return value is ignored!
    signer.verify(b"Transaction #1042", sig, pk)`
  },
  {
    name: "5. Hardcoded Cryptographic Secret Key",
    category: "Key Management",
    code: `# Flaw: Hardcoded secret key committed to source code
private_key = b"super_secret_pqc_signing_key_hex_0x99281a"
`
  },
  {
    name: "6. Deprecated FIPS Draft Names (Kyber512)",
    category: "FIPS Compliance",
    code: `import oqs

# Flaw: Uses pre-standard draft identifier 'Kyber512' instead of 'ML-KEM-512'
with oqs.KeyEncapsulation("Kyber512") as kem:
    public_key = kem.generate_keypair()`
  },
  {
    name: "7. Stateful Hash-Based Signature Risk (LMS)",
    category: "Signature Security",
    code: `import oqs

# Flaw: Stateful signatures require atomic non-volatile counter tracking
with oqs.Signature("LMS") as signer:
    pk = signer.generate_keypair()
    sig = signer.sign(b"Firmware v2.1")`
  },
  {
    name: "8. Insecure Hybrid Secret Combination (XOR)",
    category: "Hybrid Cryptography",
    code: `classical_secret = get_classical_shared_secret()
pqc_secret = get_pqc_shared_secret()

# Flaw: Naive byte-by-byte XOR combination of classical and PQC secrets
hybrid_secret = bytes(
    a ^ b for a, b in zip(classical_secret, pqc_secret)
)

use_key(hybrid_secret)`
  },
  {
    name: "9. Compliant NIST FIPS 203 & 204 Implementation",
    category: "Clean Baseline",
    code: `import oqs
import secrets

message = b"Clean Post-Quantum Payload"

# Secure random entropy
custom_salt = secrets.token_bytes(32)

# NIST FIPS 204 Standardized Digital Signature
with oqs.Signature("ML-DSA-65") as signer:
    public_key = signer.generate_keypair()
    signature = signer.sign(message)

    # Explicit verification check
    is_valid = signer.verify(message, signature, public_key)
    assert is_valid, "Signature validation failed!"`
  }
];

interface Finding {
  rule_id?: string;
  category?: string;
  severity: string;
  type: string;
  algorithm?: string;
  api?: string;
  line?: number;
  message?: string;
  recommendation?: string;
  cwe?: string;
  nist_ref?: string;
}

interface RuleMeta {
  rule_id: string;
  name: string;
  category: string;
  severity: string;
  cwe: string;
  nist_ref: string;
  description: string;
}

export default function App() {
  const [selectedScenarioIndex, setSelectedScenarioIndex] = useState<number>(0);
  const [code, setCode] = useState<string>(SCENARIOS[0].code);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [readinessScore, setReadinessScore] = useState<number | null>(null);
  const [grade, setGrade] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>("");
  const [activeRules, setActiveRules] = useState<RuleMeta[]>([]);
  const [showRulesCatalog, setShowRulesCatalog] = useState<boolean>(false);

  // Auto-Fix state
  const [diffModalOpen, setDiffModalOpen] = useState<boolean>(false);
  const [fixedCode, setFixedCode] = useState<string>("");
  const [appliedFixes, setAppliedFixes] = useState<string[]>([]);
  const [diffText, setDiffText] = useState<string>("");
  const [fixing, setFixing] = useState<boolean>(false);

  useEffect(() => {
    // Fetch registered rules catalog from backend
    fetch("http://127.0.0.1:5000/api/rules")
      .then((res) => res.json())
      .then((data) => {
        if (data.success && data.rules) {
          setActiveRules(data.rules);
        }
      })
      .catch(() => {
        // Backend not yet running or network error
      });
  }, []);

  const handleScenarioChange = (index: number) => {
    setSelectedScenarioIndex(index);
    setCode(SCENARIOS[index].code);
    setFindings([]);
    setReadinessScore(null);
    setGrade("");
    setError("");
  };

  const analyzeCode = async (overrideCode?: string) => {
    const targetCode = overrideCode !== undefined ? overrideCode : code;
    setLoading(true);
    setError("");
    setFindings([]);

    try {
      const res = await fetch("http://127.0.0.1:5000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: targetCode }),
      });

      if (!res.ok) throw new Error("Backend returned an error.");

      const data = await res.json();
      setFindings(data.findings || []);
      setReadinessScore(data.readiness_score !== undefined ? data.readiness_score : null);
      setGrade(data.grade || "");
    } catch {
      setError("Cannot connect to CryptoAPI-Safe backend. Make sure Flask server is running at http://127.0.0.1:5000.");
    } finally {
      setLoading(false);
    }
  };

  const requestAutoFix = async () => {
    setFixing(true);
    try {
      const res = await fetch("http://127.0.0.1:5000/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });

      if (!res.ok) throw new Error("Failed to generate auto-fix.");

      const data = await res.json();
      if (data.success && data.has_changes) {
        setFixedCode(data.fixed_code);
        setAppliedFixes(data.applied_fixes || []);
        setDiffText(data.diff || "");
        setDiffModalOpen(true);
      } else {
        alert("No automated fixes available for this snippet yet.");
      }
    } catch {
      alert("Failed to connect to backend remediation engine.");
    } finally {
      setFixing(false);
    }
  };

  const handleApplyFix = (newCode: string) => {
    setCode(newCode);
    setDiffModalOpen(false);
    analyzeCode(newCode);
  };

  const clearCode = () => {
    setCode("");
    setFindings([]);
    setReadinessScore(null);
    setGrade("");
    setError("");
  };

  const getGradeBadgeColor = (gradeStr: string) => {
    switch (gradeStr) {
      case "A":
        return "bg-emerald-100 text-emerald-800 border-emerald-300";
      case "B":
        return "bg-blue-100 text-blue-800 border-blue-300";
      case "C":
        return "bg-yellow-100 text-yellow-800 border-yellow-300";
      case "D":
        return "bg-orange-100 text-orange-800 border-orange-300";
      case "F":
      default:
        return "bg-red-100 text-red-800 border-red-300";
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      {/* Header */}
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight">CryptoAPI-Safe</h1>
              <span className="rounded-md bg-blue-600 px-2 py-0.5 text-xs font-bold text-white">v2.0</span>
            </div>
            <p className="text-sm text-slate-500">Post-Quantum Cryptographic API Misuse &amp; Quantum-Readiness Analyzer</p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowRulesCatalog(!showRulesCatalog)}
              className="rounded-lg border border-slate-300 bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-200"
            >
              {showRulesCatalog ? "Hide Rule Catalog" : `View Rules Catalog (${activeRules.length || 8})`}
            </button>
            <div className="rounded-full bg-emerald-100 px-4 py-1.5 text-sm font-medium text-emerald-700">
              ● Engine Online
            </div>
          </div>
        </div>
      </header>

      {/* Rules Catalog Panel */}
      {showRulesCatalog && (
        <section className="border-b border-slate-200 bg-slate-100 px-6 py-5">
          <div className="mx-auto max-w-7xl">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-600">Active Modular Rule Catalog</h3>
            <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {(activeRules.length > 0 ? activeRules : [
                { rule_id: "PQC-KEY-001", name: "PQC Key Confusion", category: "Key Management", cwe: "CWE-327", nist_ref: "FIPS 203/204" },
                { rule_id: "PQC-LEGACY-002", name: "Legacy Quantum-Vulnerable", category: "Vulnerability", cwe: "CWE-327", nist_ref: "SP 800-227" },
                { rule_id: "PQC-RNG-003", name: "Weak Randomness (PRNG)", category: "Randomness", cwe: "CWE-338", nist_ref: "SP 800-90A" },
                { rule_id: "PQC-SIG-004", name: "Ignored Verification", category: "Verification", cwe: "CWE-347", nist_ref: "FIPS 204" },
                { rule_id: "PQC-SEC-005", name: "Hardcoded Secret Keys", category: "Key Management", cwe: "CWE-798", nist_ref: "SP 800-57" },
                { rule_id: "PQC-FIPS-006", name: "Deprecated Draft Names", category: "Compliance", cwe: "CWE-1026", nist_ref: "FIPS 203/204/205" },
                { rule_id: "PQC-SIG-007", name: "Stateful Signature Risk", category: "Signature Security", cwe: "CWE-327", nist_ref: "SP 800-208" },
                { rule_id: "PQC-HYB-008", name: "Insecure Hybrid KDF", category: "Hybrid Cryptography", cwe: "CWE-327", nist_ref: "SP 800-56C" },
              ]).map((r, i) => (
                <div key={i} className="rounded-lg border border-slate-200 bg-white p-3 shadow-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-blue-600">{r.rule_id}</span>
                    <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-600">{r.cwe}</span>
                  </div>
                  <h4 className="mt-1 text-xs font-semibold text-slate-800">{r.name}</h4>
                  <p className="mt-1 text-[11px] text-slate-500">{r.nist_ref}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      <main className="mx-auto max-w-7xl px-6 py-8">
        {/* Banner */}
        <section className="mb-8">
          <div className="mb-3 inline-flex rounded-full bg-blue-100 px-3 py-1 text-sm font-medium text-blue-700">
            NIST FIPS 203, 204, 205 Standards Aligned
          </div>
          <h2 className="text-4xl font-bold tracking-tight">Post-Quantum Cryptographic Code Auditor</h2>
          <p className="mt-3 max-w-3xl text-slate-600">
            Detect cryptographic API misuse, quantum-vulnerable algorithms (Shor's Algorithm / HNDL), weak entropy, and compliance violations using semantic AST analysis.
          </p>
        </section>

        {/* Top Metrics Cards */}
        <section className="mb-8 grid gap-4 md:grid-cols-4">
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm text-slate-500">Active Rule Engine</p>
            <p className="mt-2 text-3xl font-bold text-blue-600">{activeRules.length || 8}</p>
            <p className="mt-1 text-sm text-slate-500">Standards-aligned rules</p>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm text-slate-500">Quantum Readiness</p>
            <div className="mt-2 flex items-baseline gap-2">
              <p className="text-3xl font-bold text-slate-900">
                {readinessScore !== null ? `${readinessScore}%` : "—"}
              </p>
              {grade && (
                <span className={`rounded-md border px-2 py-0.5 text-xs font-bold ${getGradeBadgeColor(grade)}`}>
                  Grade {grade}
                </span>
              )}
            </div>
            <p className="mt-1 text-sm text-slate-500">NIST compliance index</p>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm text-slate-500">Current Findings</p>
            <p className="mt-2 text-3xl font-bold text-red-600">{findings.length}</p>
            <p className="mt-1 text-sm text-slate-500">Issues detected</p>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm text-slate-500">Supported Standards</p>
            <p className="mt-2 text-3xl font-bold text-emerald-600">FIPS</p>
            <p className="mt-1 text-sm text-slate-500">203 · 204 · 205 · SP 800-208</p>
          </div>
        </section>

        {/* Two-Column Editor & Findings */}
        <section className="grid gap-6 lg:grid-cols-2">
          {/* Left Column: Code Editor */}
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <div className="flex flex-col gap-2 border-b border-slate-200 px-5 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="font-semibold">Source Code</h3>
                <p className="text-xs text-slate-500">Select a test scenario or paste custom Python code</p>
              </div>

              {/* Scenario Preset Selector */}
              <div className="flex items-center gap-2">
                <select
                  value={selectedScenarioIndex}
                  onChange={(e) => handleScenarioChange(Number(e.target.value))}
                  className="rounded-lg border border-slate-300 bg-white px-2 py-1.5 text-xs font-medium text-slate-700 outline-none focus:border-blue-500"
                >
                  {SCENARIOS.map((s, idx) => (
                    <option key={idx} value={idx}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="p-5">
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                spellCheck={false}
                className="h-[430px] w-full resize-none rounded-lg border border-slate-300 bg-slate-950 p-5 font-mono text-sm leading-6 text-slate-100 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                placeholder="Paste Python cryptographic code here..."
              />

              <div className="mt-4 flex gap-3">
                <button
                  onClick={() => analyzeCode()}
                  disabled={loading || !code.trim()}
                  className="flex-1 rounded-lg bg-blue-600 px-5 py-3 font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-slate-400"
                >
                  {loading ? "Analyzing AST & Semantic Rules..." : "🔍 Run Security Analysis"}
                </button>

                <button
                  onClick={clearCode}
                  className="rounded-lg border border-slate-300 bg-white px-5 py-3 font-semibold text-slate-700 hover:bg-slate-50"
                >
                  Clear
                </button>
              </div>
            </div>
          </div>

          {/* Right Column: Security Analysis Results */}
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
              <div>
                <h3 className="font-semibold">Security Findings</h3>
                <p className="text-xs text-slate-500">Cryptographic flaws, compliance violations, and recommendations</p>
              </div>
              {readinessScore !== null && (
                <span className={`rounded-lg border px-3 py-1 text-xs font-bold ${getGradeBadgeColor(grade)}`}>
                  Quantum Readiness: {readinessScore}% ({grade})
                </span>
              )}
            </div>

            <div className="max-h-[530px] overflow-y-auto p-5">
              {error && (
                <div className="mb-5 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>
              )}

              {!error && findings.length === 0 && (
                <div className="flex min-h-[400px] flex-col items-center justify-center text-center">
                  <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-emerald-100 text-3xl text-emerald-700">
                    ✓
                  </div>
                  <h4 className="text-lg font-semibold">
                    {readinessScore === 100 ? "Clean Cryptographic Baseline!" : "No Findings Yet"}
                  </h4>
                  <p className="mt-2 max-w-sm text-sm text-slate-500">
                    {readinessScore === 100
                      ? "No cryptographic API misuse or quantum-vulnerable algorithms detected in this snippet."
                      : "Select a scenario and click 'Run Security Analysis' to evaluate."}
                  </p>
                </div>
              )}

              {findings.length > 0 && (
                <div className="space-y-4">
                  {/* One-Click Auto-Fix Banner */}
                  <div className="flex flex-col gap-3 rounded-xl border border-blue-200 bg-linear-to-r from-blue-50 to-indigo-50 p-4 sm:flex-row sm:items-center sm:justify-between shadow-xs">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="flex h-6 w-6 items-center justify-center rounded-md bg-blue-600 text-xs font-bold text-white shadow-xs">⚡</span>
                        <h4 className="text-sm font-bold text-blue-950">One-Click Auto-Fix Available</h4>
                      </div>
                      <p className="mt-1 text-xs text-blue-800">
                        Automatically transform detected flaws to NIST FIPS standards with interactive diff preview.
                      </p>
                    </div>

                    <button
                      onClick={requestAutoFix}
                      disabled={fixing}
                      className="shrink-0 rounded-lg bg-blue-600 px-4 py-2 text-xs font-bold text-white shadow-xs hover:bg-blue-700 transition disabled:bg-slate-400 cursor-pointer"
                    >
                      {fixing ? "Generating Patches..." : "⚡ Review & Apply Auto-Fix"}
                    </button>
                  </div>

                  {findings.map((finding, index) => (
                    <div
                      key={index}
                      className={`rounded-xl border p-5 ${
                        finding.severity === "CRITICAL"
                          ? "border-red-300 bg-red-50/70"
                          : finding.severity === "HIGH"
                          ? "border-orange-200 bg-orange-50/50"
                          : "border-yellow-200 bg-yellow-50/50"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`rounded-full px-2.5 py-0.5 text-xs font-bold text-white ${
                                finding.severity === "CRITICAL"
                                  ? "bg-red-700"
                                  : finding.severity === "HIGH"
                                  ? "bg-red-600"
                                  : "bg-amber-600"
                              }`}
                            >
                              {finding.severity}
                            </span>
                            {finding.rule_id && (
                              <span className="font-mono text-xs font-bold text-slate-700">{finding.rule_id}</span>
                            )}
                            {finding.cwe && (
                              <span className="rounded bg-white px-2 py-0.5 text-xs font-medium text-slate-600 border border-slate-200">
                                {finding.cwe}
                              </span>
                            )}
                            {finding.nist_ref && (
                              <span className="rounded bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800">
                                {finding.nist_ref}
                              </span>
                            )}
                          </div>

                          <h4 className="mt-2 text-base font-bold text-slate-900">{finding.type}</h4>
                        </div>

                        <div className="rounded-lg bg-white px-3 py-1.5 text-xs font-bold text-slate-700 border border-slate-200">
                          Line {finding.line}
                        </div>
                      </div>

                      <div className="mt-3 grid gap-3 sm:grid-cols-2">
                        <div className="rounded-lg bg-white p-2.5 border border-slate-100">
                          <p className="text-[11px] font-medium uppercase text-slate-500">Target / Primitive</p>
                          <p className="mt-0.5 font-semibold text-xs text-slate-800">{finding.algorithm}</p>
                        </div>

                        <div className="rounded-lg bg-white p-2.5 border border-slate-100">
                          <p className="text-[11px] font-medium uppercase text-slate-500">API Call</p>
                          <p className="mt-0.5 font-mono text-xs font-semibold text-slate-800">{finding.api}</p>
                        </div>
                      </div>

                      <div className="mt-3">
                        <p className="text-[11px] font-medium uppercase text-slate-500">Risk Assessment</p>
                        <p className="mt-0.5 text-xs leading-5 text-slate-700">{finding.message}</p>
                      </div>

                      <div className="mt-3 rounded-lg border border-blue-200 bg-blue-50 p-3">
                        <p className="text-[11px] font-bold uppercase text-blue-700">Remediation</p>
                        <p className="mt-0.5 text-xs leading-5 text-blue-900">{finding.recommendation}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Educational Architecture Workflow */}
        <section className="mt-8 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="text-lg font-semibold">How the Modular Post-Quantum Engine Works</h3>
          <div className="mt-5 grid gap-4 md:grid-cols-4">
            <Step number="01" title="Semantic AST Parsing" description="Source code is parsed into Python AST; variable roles (keys, seeds, secrets) are tracked." />
            <Step number="02" title="Context Symbol Table" description="Variables are mapped to roles (PUBLIC_KEY, PRIVATE_KEY) regardless of naming conventions." />
            <Step number="03" title="8-Rule Security Suite" description="Evaluates Key Roles, Shor's Vulnerability, Weak Entropy, Signature Checks, and FIPS naming." />
            <Step number="04" title="Audit & Score" description="Calculates Quantum Readiness Score (0-100%), maps CWEs, and produces remediation." />
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-200 bg-white py-6">
        <div className="mx-auto max-w-7xl px-6 text-center text-sm text-slate-500">
          CryptoAPI-Safe · Post-Quantum Cryptographic API Misuse Detection &amp; Readiness Analyzer · NIST FIPS 203/204/205
        </div>
      </footer>

      {/* Auto-Fix Diff Viewer Modal */}
      <DiffViewer
        isOpen={diffModalOpen}
        onClose={() => setDiffModalOpen(false)}
        onApply={handleApplyFix}
        originalCode={code}
        fixedCode={fixedCode}
        appliedFixes={appliedFixes}
        diffText={diffText}
      />
    </div>
  );
}

function Step({ number, title, description }: { number: string; title: string; description: string }) {
  return (
    <div className="rounded-lg border border-slate-200 p-4">
      <span className="text-sm font-bold text-blue-600">{number}</span>
      <h4 className="mt-2 font-semibold text-sm">{title}</h4>
      <p className="mt-1 text-xs leading-5 text-slate-500">{description}</p>
    </div>
  );
}
