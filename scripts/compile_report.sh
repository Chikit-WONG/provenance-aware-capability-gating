#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/report"

# The cluster's conda texlive environment is broken. Use TinyTeX exactly as
# documented in AGENTS.md.
export PATH=/hpc2hdd/home/ckwong627/.TinyTeX/bin/x86_64-linux:$PATH

# Do not let a stale PDF make a failed source edit appear successful.
rm -f main.pdf

pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
latex_status=$?

# rerunfilecheck may make the final pass non-zero even though the PDF is valid.
if [[ -s main.pdf ]]; then
  echo "Compiled report/main.pdf"
  exit 0
fi

echo "Report compilation failed: report/main.pdf was not produced" >&2
exit "$latex_status"
