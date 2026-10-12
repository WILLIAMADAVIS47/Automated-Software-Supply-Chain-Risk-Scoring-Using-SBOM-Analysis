# SBOM Supply Chain Risk Scoring

This repository holds the prototype tool, called sbomrisk, for the CS 690 Graduate Research Project "SBOM Supply Chain Risk Scoring: A Contextual Component Risk Ranking Framework" by William A. Davis (advisor: Dr. Omar Ochoa), Embry-Riddle Aeronautical University, Fall 2026.

The tool reads CycloneDX SBOMs and rebuilds each application's dependency graph. In later phases it will add vulnerability data and rank components with a rule-based weighted score, compared against a CVSS-only baseline.

## Documents

All project documents are Word files in the `docs` folder, listed in the order the work was done:

- Task B Tool Selection
- Task C Test Projects
- D1 Scoring Specification
- Validation Report
- Setup and Run Guide (start here to install and run the tool)

## Quick start (Windows PowerShell)

Open PowerShell inside the project folder (the one that contains pyproject.toml), then run

```
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
sbomrisk inspect data\sboms\pygoat-v2.0.1.cdx.json
```

## Folder layout

- `src/sbomrisk`: the parser, dependency graph and command-line tool
- `tests`: automated tests and a small hand-built SBOM
- `scripts`: SBOM generation, PyGoat root fix and validation scripts
- `data/sboms`: SBOMs for the four test projects
- `data/tables`: dependency depth tables for each project (CSV files that open in Excel)
- `data/validation`: package manager reference outputs used for validation
- `docs`: project documents
