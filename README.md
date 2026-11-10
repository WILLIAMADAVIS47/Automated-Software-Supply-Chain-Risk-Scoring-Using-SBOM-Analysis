# SBOM Supply Chain Risk Scoring

This repository holds the prototype tool, called sbomrisk, for the CS 690 Graduate Research Project "SBOM Supply Chain Risk Scoring: A Contextual Component Risk Ranking Framework" by William A. Davis (advisor: Dr. Omar Ochoa), Embry-Riddle Aeronautical University, Fall 2026.

The tool reads CycloneDX SBOMs, rebuilds each application's dependency graph, and looks up known vulnerabilities for every component in OSV, with CVSS scores from NVD, exploit likelihood from FIRST EPSS, and known exploitation from the CISA KEV catalog. It then ranks the vulnerable components with the rule-based weighted score defined in the D1 Scoring Specification, explains each rank in one sentence, and compares the result with a CVSS-only baseline.

## Documents

All project documents are in the `docs` folder, listed in the order the work was done:

- Task B Tool Selection
- Task C Test Projects
- D1 Scoring Specification
- Validation Report
- D2 Prototype Implementation
- Setup and Run Guide (start here to install and run the tool)
- D3 Evaluation Results
- D4 Final Report
- GRP Presentation (defense slides)

## Quick start (Windows PowerShell)

Open PowerShell inside the project folder (the one that contains pyproject.toml), then run:

```
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
sbomrisk inspect data\sboms\pygoat-v2.0.1.cdx.json
sbomrisk enrich data\sboms\pygoat-v2.0.1.cdx.json
sbomrisk rank data\sboms\pygoat-v2.0.1.cdx.json
```

The enrich command needs internet access. It saves every answer it receives in a `cache` folder, so running it again (or adding `--offline`) repeats the analysis without contacting the services. Results are written to `results\<sbom name>-<date>\enrichment.json`. Without an NVD API key, NVD allows only a few requests per minute, so a first run can take a while. A free key from https://nvd.nist.gov/developers/request-an-api-key makes it much faster; set it in PowerShell before running with `$env:NVD_API_KEY="your-key"`.

The rank command scores the components found by the most recent enrich run and writes the ranking (JSON and CSV), the CVSS-only baseline, the components that were not ranked, and a run record into the same results folder. The default weights are in `src/sbomrisk/weights.json`; `--weights other.json` runs with different ones.

Once the test projects have been enriched, `sbomrisk evaluate` compares each ranking with its baseline (top-ten differences and Kendall's tau), runs the 20-run weight sensitivity analysis for each project, and writes the results to `results\evaluation-<date>`.

## Folder layout

- `src/sbomrisk`: the parser, dependency graph, vulnerability enrichment, scoring and ranking, evaluation and command-line tool
- `tests`: automated tests and a small hand-built SBOM
- `scripts`: SBOM generation, root component fix and validation scripts
- `data/sboms`: SBOMs for the six test projects (Juice Shop, Etherpad and Wiki.js in JavaScript, Gitea in Go, PyGoat in Python, WebGoat in Java)
- `data/tables`: dependency depth tables for each project (CSV files that open in Excel)
- `data/validation`: package manager reference outputs used for validation
- `docs`: project documents
