interface DiffViewerProps {
  isOpen: boolean;
  onClose: () => void;
  onApply: (fixedCode: string) => void;
  originalCode: string;
  fixedCode: string;
  appliedFixes: string[];
  diffText: string;
}

export default function DiffViewer({
  isOpen,
  onClose,
  onApply,
  originalCode,
  fixedCode,
  appliedFixes,
}: DiffViewerProps) {
  if (!isOpen) return null;

  const originalLines = originalCode.split("\n");
  const fixedLines = fixedCode.split("\n");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4 sm:p-6 overflow-y-auto">
      <div className="relative w-full max-w-5xl rounded-2xl bg-white shadow-2xl border border-slate-200 overflow-hidden my-8">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-6 py-4">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-600 text-white font-bold text-sm">⚡</span>
              <h3 className="text-lg font-bold text-slate-900">One-Click Auto-Fix Preview</h3>
              <span className="rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-semibold text-emerald-800">
                NIST Standardized
              </span>
            </div>
            <p className="mt-0.5 text-xs text-slate-500">
              Review proposed cryptographic patches before applying them to your source code.
            </p>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-200 hover:text-slate-600 transition"
          >
            ✕
          </button>
        </div>

        {/* Applied Patches List */}
        {appliedFixes.length > 0 && (
          <div className="border-b border-slate-200 bg-blue-50/70 px-6 py-3">
            <p className="text-xs font-bold uppercase tracking-wider text-blue-800">
              {appliedFixes.length} Automated Fix{appliedFixes.length > 1 ? "es" : ""} Ready to Apply:
            </p>
            <ul className="mt-1.5 space-y-1">
              {appliedFixes.map((fix, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-blue-950">
                  <span className="text-emerald-600 font-bold">✓</span>
                  <span>{fix}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Side-by-Side Comparison */}
        <div className="p-6">
          <div className="grid gap-4 lg:grid-cols-2">
            
            {/* Left: Original Code */}
            <div className="rounded-xl border border-red-200 bg-slate-950 overflow-hidden shadow-xs">
              <div className="flex items-center justify-between border-b border-slate-800 bg-red-950/40 px-4 py-2 text-xs font-semibold text-red-300">
                <span>Original Code (Vulnerable)</span>
                <span className="rounded bg-red-900/60 px-2 py-0.5 text-[10px] text-red-200 font-mono">
                  {originalLines.length} lines
                </span>
              </div>
              <div className="max-h-[380px] overflow-y-auto p-4 font-mono text-xs leading-5 text-slate-300">
                {originalLines.map((line, idx) => (
                  <div key={idx} className="flex gap-3 hover:bg-slate-900/60">
                    <span className="w-6 shrink-0 select-none text-right text-slate-600 font-mono">
                      {idx + 1}
                    </span>
                    <span className="whitespace-pre overflow-x-auto text-slate-200">{line || " "}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: Remediated Code */}
            <div className="rounded-xl border border-emerald-300 bg-slate-950 overflow-hidden shadow-xs">
              <div className="flex items-center justify-between border-b border-slate-800 bg-emerald-950/40 px-4 py-2 text-xs font-semibold text-emerald-300">
                <span>Remediated Code (NIST Compliant)</span>
                <span className="rounded bg-emerald-900/60 px-2 py-0.5 text-[10px] text-emerald-200 font-mono">
                  {fixedLines.length} lines
                </span>
              </div>
              <div className="max-h-[380px] overflow-y-auto p-4 font-mono text-xs leading-5 text-emerald-300">
                {fixedLines.map((line, idx) => (
                  <div key={idx} className="flex gap-3 hover:bg-slate-900/60">
                    <span className="w-6 shrink-0 select-none text-right text-slate-600 font-mono">
                      {idx + 1}
                    </span>
                    <span className="whitespace-pre overflow-x-auto text-emerald-200 font-semibold">{line || " "}</span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        </div>

        {/* Modal Actions Footer */}
        <div className="flex items-center justify-between border-t border-slate-200 bg-slate-50 px-6 py-4">
          <button
            onClick={onClose}
            className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition"
          >
            Cancel / Keep Current Code
          </button>

          <button
            onClick={() => onApply(fixedCode)}
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-blue-700 transition"
          >
            <span>⚡ Accept &amp; Apply Auto-Fix</span>
          </button>
        </div>

      </div>
    </div>
  );
}
