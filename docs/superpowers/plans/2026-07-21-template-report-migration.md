# Template-Conformant Report Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize `report/main.tex` to follow `Template_ProjectReport/main.tex` while preserving the verified experiment and inserting the four confirmed authors.

**Architecture:** Replace the custom `article` wrapper with the template's `IEEEtran` journal wrapper and section skeleton. Move existing prose into the template's attack/defense, evaluation, analysis, peer-evaluation, conclusion, and appendix locations; keep generated results included from the existing artifact directories. No source, frozen plan, corpus, or artifact data changes are allowed.

**Tech Stack:** LaTeX, IEEEtran, TinyTeX, existing `report/generated/results_summary.tex`, local BibTeX database `report/references.bib`.

## Global Constraints

- Work only on local branch `ckw`; do not push to `origin/ckw`.
- Preserve all reported numerical values, result tables, figures, citations, limitations, ethics, reproducibility, and AI-use disclosure.
- Use author names and IDs exactly as confirmed: Chi Kit WONG (50012338), Haotian WANG (50027503), Guanrun PENG (50013277), Boyong HOU (50012560).
- Leave specific contribution cells blank and state explicitly that all four members made equal contributions.
- Compile with `/hpc2hdd/home/ckwong627/.TinyTeX/bin/x86_64-linux/pdflatex` through `scripts/compile_report.sh`.

---

### Task 1: Replace the report wrapper with the course template skeleton

**Files:**
- Modify: `report/main.tex`
- Reference: `/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/Template_ProjectReport/main.tex`

**Interfaces:**
- The document starts with `\documentclass[journal]{IEEEtran}` and the template packages.
- It contains the template sections `Introduction`, `Background \& Motivation`,
  `Target System Description`, `Threat Model`, `Attack \& Defense Design`,
  `Evaluation`, `Analysis and Discussion`, `Peer Evaluation`, `Conclusion`, and
  `Appendices`.
- All existing prose is retained under one of the mapped sections in Task 1,
  Step 2.

- [ ] **Step 1: Write the IEEEtran preamble and author block.**

  Keep the template's packages and spacing setup, add only packages/commands
  needed by the existing equations, tables, URLs, and figures, and replace the
  template author block with the four confirmed names and IDs.

- [ ] **Step 2: Move existing content into the template section order.**

  Use this exact mapping: Background and Design Principles to Background &
  Motivation; System Design to Target System Description; Offline Attack Corpus
  and attack protocol to Attack & Defense Design/Attacks; Defense arms to
  Attack & Defense Design/Defenses; Experimental Method to Evaluation/
  Experimental Setup; Results to Evaluation/Results; interpretation, limitations,
  ethics, reproducibility, and AI-use disclosure to Analysis and Discussion.

- [ ] **Step 3: Add peer-evaluation and conclusion content without inventing roles.**

  Add `Individual Contribution Statements` and
  `Teammate Evaluation Scores & Justifications` subsections. List all four
  names/IDs, leave the specific-contribution cells empty, and add the sentence
  `All four members made equal contributions.` Do not fabricate scores. Add a
  concise Conclusion derived from the existing result and limitation text.

- [ ] **Step 4: Add an appendix with reproducibility pointers.**

  Move only detailed artifact paths, frozen-plan names, analysis directories,
  and compilation/replay commands into an appendix; do not duplicate or alter
  result values.

### Task 2: Compile and inspect the template-conformant PDF

**Files:**
- Generate: `report/main.pdf`
- Inspect: `report/main.log`

- [ ] **Step 1: Compile with TinyTeX.**

  Run `bash scripts/compile_report.sh` and require a non-empty PDF. Treat only
  expected IEEEtran overfull-box warnings as non-fatal; stop on missing class,
  bibliography errors, undefined control sequences, or absent figures.

- [ ] **Step 2: Verify the structure and metadata.**

  Check the source for `IEEEtran`, all template section names, all four author
  names and IDs, the equal-contribution sentence, and no old article wrapper or
  unfilled author metadata.

- [ ] **Step 3: Verify preserved results.**

  Check that the report still contains the original/hardened counts, the
  `-0.50` and `-0.33` contrasts, and the `16/16` sink-pressure result. Run
  `git diff --check` and the complete unit-test suite.

### Task 3: Commit the report-only migration

- [ ] **Step 1: Review the diff and status.**

  Confirm that only the report source/PDF and the migration plan/spec changed;
  no source code, frozen plan, corpus, or analysis artifact is modified.

- [ ] **Step 2: Commit locally.**

  ```bash
  git add report/main.tex report/main.pdf
  git commit -m "docs: reformat report with course template"
  ```

  Do not push.
