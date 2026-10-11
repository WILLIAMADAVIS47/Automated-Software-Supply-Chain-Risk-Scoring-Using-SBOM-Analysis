# Parser and Dependency-Graph Validation (Task F)

**Date:** October 11, 2026 | **Script:** `scripts/validate_graph.py` | **Reference outputs:** `data/validation/`

## Question

Does the parser find the same components, versions and dependency depths that each ecosystem's own package manager reports? Depth matters here because it is scoring factor D. The check compares `sbomrisk`'s view of each SBOM against an independent tool run on the same project.

## Results

| Project | Reference tool | Components matched (name + version) | Depth or edges matched | Result |
|---|---|---|---|---|
| Juice Shop (npm) | `npm ls --all --omit=dev --package-lock-only --json` | 645 of 645 (100%) | Depth: 645 of 645 (100%) | PASS |
| PyGoat (PyPI) | `pipdeptree --json` | 33 of 33 (100%) | Edges: 25 of 25, none extra | PASS (after fix 3) |
| Gitea (Go) | `go list -m -json all` | 231 of 231 in Go's build list, same versions | n/a (Go has no per-module tree) | PASS |
| WebGoat (Maven) | `mvn dependency:tree -Dscope=runtime` | 179 of 179 (100%); 11 more in SBOM only (see note 4) | Depth: 179 of 179 (100%) | PASS |

**Independent re-run (Oct 11, 2026):** William A. Davis ran the package on Windows (Python 3.13.9, pytest 9.1.1) from the GitHub copy. All 16 tests passed. `sbomrisk inspect` reproduced every component, edge, direct-dependency and depth count above, and the npm, pip and Go checks all printed `RESULT: PASS` with identical numbers.

## Problems found and fixed

1. **Duplicate npm installs (validator bug).** npm can install one package version in two places; for example, debug@4.4.3 sits under both sequelize and sqlite3. The first version of the check kept whichever copy it saw last, and 14 packages appeared to differ in depth. The fix is to use the shallowest copy. That gives 100% agreement. **This also applies to scoring:** the spec now says duplicate installs are merged into one ranked entry at their shallowest depth.
2. **npm aliases and Go replace directives (validator bug).** For example, `string-width-cjs` is an alias for `string-width`, and Gitea replaces `github.com/nektos/act` with `gitea.com/gitea/act`. The check now resolves both.
3. **Optional "extras" recorded as real dependencies (SBOM data bug, PyGoat).** `cyclonedx-py` listed 10 edges that pip doesn't treat as required, such as cryptography → pytz from cryptography's *test* extra and Django → argon2-cffi from an optional extra. Those false edges changed three packages' depths and hid cryptography's status as a direct dependency. `add_root_component.py --required-edges` now removes any edge pipdeptree doesn't confirm. PyGoat went from 14 to 16 direct dependencies, and its maximum depth went from 4 to 3.

4. **Maven hides some runtime libraries when filtering by scope (tool behavior, not a bug).** The SBOM has 11 runtime libraries that `mvn dependency:tree -Dscope=runtime` doesn't print, including spring-security-core and -web, byte-buddy, json-smart and commons-logging. Each one also sits closer to the root under a *test* dependency (for example spring-security-test → spring-security-core is 2 levels, versus 3 through the runtime path). Maven draws a library only once, at its nearest position, so it draws these under the test dependency. The runtime filter then removes the test dependency's subtree, and the library disappears from the printout even though it ships at runtime. The SBOM is correct to include them, at their runtime depth. **Confirmed** from the full tree (no `-Dscope` filter):

```
+- org.springframework.security:spring-security-test:jar:7.1.1:test
|  +- org.springframework.security:spring-security-core:jar:7.1.1:compile
|  +- com.jayway.jsonpath:json-path:jar:2.10.0:test
|  +- net.minidev:json-smart:jar:2.6.0:compile
|  +- org.assertj:assertj-core:jar:3.27.7:test
|  |  \- net.bytebuddy:byte-buddy:jar:1.18.11:runtime
```

Each library is marked compile or runtime but drawn under a test-scoped parent.

The Maven check was run by William A. Davis on Windows on Oct 11, 2026, with Java 25 and the Maven wrapper shipped with WebGoat.

## Not covered by this check

- **Go depth.** Go's module graph lists every module the build considered, not a parent-child tree of what's linked. Only membership and versions are checked.
- **Vulnerabilities and scores.** These don't exist until enrichment (Task G) and scoring (Task H). Validating those against an independent scanner is planned for the evaluation (D3).
