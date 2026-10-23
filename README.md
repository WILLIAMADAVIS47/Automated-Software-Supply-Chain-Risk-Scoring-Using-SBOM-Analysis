# SBOM Supply Chain Risk Scoring

This repository holds the prototype tool, called sbomrisk, for the CS 690 Graduate Research Project "SBOM Supply Chain Risk Scoring: A Contextual Component Risk Ranking Framework" by William A. Davis (advisor: Dr. Omar Ochoa), Embry-Riddle Aeronautical University, Fall 2026.

The tool reads CycloneDX SBOMs, rebuilds each application's dependency graph, and looks up known vulnerabilities for every component in OSV, with CVSS scores from NVD, exploit likelihood from FIRST EPSS, and known exploitation from the CISA KEV catalog. A later phase will rank components with a rule-based weighted score, compared against a CVSS-only baseline.

## Documents

All project documents are Word files in the `docs` folder, listed in the order the work was done:

- Task B Tool Selection
- Task C Test Projects
- D1 Scoring Specification
- Validation Report
- Setup and Run Guide (start here to install and run the tool)

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
```

The enrich command needs internet access. It saves every answer it receives in a `cache` folder, so running it again (or adding `--offline`) repeats the analysis without contacting the services. Results are written to `results\<sbom name>-<date>\enrichment.json`. Without an NVD API key, NVD allows only a few requests per minute, so a first run can take a while. A free key from https://nvd.nist.gov/developers/request-an-api-key makes it much faster; set it in PowerShell before running with `$env:NVD_API_KEY="your-key"`.

## Folder layout

- `src/sbomrisk`: the parser, dependency graph, vulnerability enrichment and command-line tool
- `tests`: automated tests and a small hand-built SBOM
- `scripts`: SBOM generation, PyGoat root fix and validation scripts
- `data/sboms`: SBOMs for the four test projects
- `data/tables`: dependency depth tables for each project (CSV files that open in Excel)
- `data/validation`: package manager reference outputs used for validation
- `docs`: project documents
