# Template-Conformant Project Report Design

## Goal

Reorganize the existing project report around the course's
`Template_ProjectReport/main.tex` structure and IEEEtran layout while retaining
all verified experimental content, result values, figures, tables, citations,
limitations, reproducibility notes, and AI-use disclosure.

## Non-goals

- Do not change source code, frozen plans, attack corpora, experiment artifacts,
  statistical calculations, or reported numerical conclusions.
- Do not invent individual contribution roles or peer-evaluation scores.
- Do not push the branch or alter the remote repository.

## Layout and author metadata

The report will use the template's `IEEEtran` journal document class, its
two-column presentation, compatible packages, IEEE bibliography style, and the
existing local `references.bib` database. The author block will list:

1. Chi Kit WONG — 50012338
2. Haotian WANG — 50027503
3. Guanrun PENG — 50013277
4. Boyong HOU — 50012560

The contribution table will contain these names and IDs while leaving the
specific-contribution cells empty. A separate statement will explicitly record
that all four members made equal contributions.

## Section mapping

The template skeleton will be preserved, with current prose moved as follows:

| Template section | Current content |
| --- | --- |
| Introduction | Current Introduction and research question |
| Background & Motivation | Background and Design Principles |
| Target System Description | System Design, agents, tools, capabilities, provenance |
| Threat Model | Current Threat Model |
| Attack & Defense Design / Attacks | Offline Attack Corpus and attack-generation protocol |
| Attack & Defense Design / Defenses | Defense arms and gateway behavior |
| Evaluation / Experimental Setup | Experimental Method, matrix, pilot gates, outcomes, evaluator |
| Evaluation / Results | Complete-factorial results and sink-pressure test |
| Analysis and Discussion | Interpretation, corpus comparison, limitations, ethics, reproducibility |
| Peer Evaluation | Team contribution table, equal-contribution statement, peer-evaluation note |
| Conclusion | A concise conclusion derived only from the existing findings and limitations |
| Appendices | Reproducibility and artifact pointers that are too detailed for the main text |

The existing limitations, ethics and safety, reproducibility, and AI-use
disclosure text will remain present, but will be grouped under Analysis and
Discussion or its subsections instead of being silently removed.

## Figures, tables, and compilation

Generated result tables and plots will continue to come from the checked-in
corpus-specific analysis directories. Wide publication tables or plots that do
not fit one IEEEtran column will use a two-column float or a controlled resize;
their source data and captions will remain unchanged. The report will be
compiled with the repository's TinyTeX script, and a non-empty `report/main.pdf`
plus a clean `git diff --check` will be required.

## Acceptance criteria

- `report/main.tex` uses `IEEEtran` and follows the template section skeleton.
- All current experimental results and linked generated artifacts remain
  represented in the report with unchanged numeric values.
- The four author names and student IDs are present.
- The contribution table has no fabricated role text, and the equal-contribution
  statement is explicit.
- The report compiles successfully with TinyTeX and produces a non-empty PDF.
- The full test suite remains passing and no experiment files are modified.
