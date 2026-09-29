# CI Integrations

ZIRAN provides ready-to-use templates for five CI/CD systems. Each template runs the `ziran ci` command as a quality gate and produces SARIF output for security dashboards.

All templates accept the same core parameters:

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| Coverage | `essential`, `standard`, `comprehensive` | `standard` | Breadth of attack vectors to test |
| Severity threshold | `critical`, `high`, `medium`, `low` | `medium` | Minimum severity that fails the gate |
| Result file | Path | `scan_results.json` | Input scan result JSON |
| SARIF file | Path | varies | Output SARIF report path |

---

## GitHub Actions

The official GitHub Action (`taoq-ai/ziran@v0`) wraps `ziran ci` with native annotations, step summaries, and SARIF upload.

```yaml
# .github/workflows/security.yml
name: Agent Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ZIRAN scan
        uses: taoq-ai/ziran@v0
        with:
          command: ci
          result-file: scan_results.json
          severity-threshold: medium
          sarif-output: results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

**Outputs:** `status`, `trust-score`, `total-findings`, `critical-findings`, `sarif-file`,
`exit-code`, `sarif-id`.

Full example: [`examples/07-cicd-quality-gate/ziran-scan.yml`](https://github.com/taoq-ai/ziran/blob/main/examples/07-cicd-quality-gate/ziran-scan.yml)

### Claude Code plugin audit

`command: audit` runs `ziran audit` over a Claude Code plugin root, an `agents/` directory, a
single agent `.md` file or Python source. With a committed allowlist baseline the step fails when
an agent gains a tool, loses its `tools:` key, appears new, or forms a new dangerous chain; the
findings are uploaded to code scanning as SARIF.

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload
  actions: read

steps:
  - uses: actions/checkout@v7
  - uses: taoq-ai/ziran@v0
    with:
      command: audit
      path: agents                          # or "." for a plugin root
      baseline: agents/ziran-baseline.json
      severity-threshold: low               # default; widenings are critical and always fail
      sarif-output: ziran-results.sarif     # default; "" disables SARIF and the upload
      ziran-version: "ziran==<pinned>"
```

| Input | Default | Used by `audit` as |
|-------|---------|--------------------|
| `path` | `""` | The audit target; overrides `source-path` when set |
| `source-path` | `.` | The audit target when `path` is empty |
| `baseline` | `""` | `--baseline FILE` (record it with `ziran audit PATH --write-baseline FILE`) |
| `severity-threshold` | `low` | `--severity` |
| `sarif-output` | `ziran-results.sarif` | `--sarif FILE`, then uploaded to code scanning; `""` disables both |

| Output | Value |
|--------|-------|
| `status` | `passed` or `failed` |
| `exit-code` | `0` passed; `1` findings at or above the threshold, or a widened agent; `2` could not run (bad path, missing or invalid baseline, unwritable SARIF path) |
| `sarif-file` | The SARIF path, when it was written |
| `sarif-id` | The code-scanning upload id; empty when nothing was uploaded |

The loop: record the baseline with `--write-baseline`, commit it, let CI check against it with
the `baseline:` input, and re-record after reviewing an intended change. Narrowing an agent never
fails the build. The upload step is `continue-on-error`, so a repository without code scanning
still gets the pass/fail result.

Full example: [`examples/07-cicd-quality-gate/claude-code-audit.yml`](https://github.com/taoq-ai/ziran/blob/main/examples/07-cicd-quality-gate/claude-code-audit.yml)
(sample plugin and baseline in [`claude-code-plugin/`](https://github.com/taoq-ai/ziran/tree/main/examples/07-cicd-quality-gate/claude-code-plugin)).

---

## GitLab CI

GitLab natively ingests SARIF via the `sast` artifact report type, so findings appear in the Security Dashboard.

```yaml
variables:
  ZIRAN_COVERAGE: "standard"
  ZIRAN_SEVERITY_THRESHOLD: "medium"

ziran-security-scan:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install ziran
  script:
    - >-
      ziran ci
      --result-file ${RESULT_FILE:-scan_results.json}
      --severity-threshold $ZIRAN_SEVERITY_THRESHOLD
      --coverage $ZIRAN_COVERAGE
      --output sarif
      --sarif-file gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
  allow_failure: false
```

Full template: [`examples/07-cicd-quality-gate/gitlab-ci.yml`](https://github.com/taoq-ai/ziran/blob/main/examples/07-cicd-quality-gate/gitlab-ci.yml)

---

## Jenkins

Requires the [Warnings Next Generation Plugin](https://plugins.jenkins.io/warnings-ng/) to display SARIF findings.

```groovy
pipeline {
    agent any
    parameters {
        choice(name: 'ZIRAN_COVERAGE',
               choices: ['essential', 'standard', 'comprehensive'],
               description: 'Coverage level')
        choice(name: 'ZIRAN_SEVERITY_THRESHOLD',
               choices: ['critical', 'high', 'medium', 'low'],
               description: 'Severity threshold')
    }
    stages {
        stage('Install Ziran') {
            steps {
                sh 'pip install ziran'
            }
        }
        stage('Security Scan') {
            steps {
                sh """
                    ziran ci \
                        --result-file ${RESULT_FILE ?: 'scan_results.json'} \
                        --severity-threshold ${params.ZIRAN_SEVERITY_THRESHOLD} \
                        --coverage ${params.ZIRAN_COVERAGE} \
                        --output sarif \
                        --sarif-file ziran-results.sarif
                """
            }
            post {
                always {
                    recordIssues tool: sarif(pattern: 'ziran-results.sarif')
                }
            }
        }
    }
}
```

Full template: [`examples/07-cicd-quality-gate/Jenkinsfile`](https://github.com/taoq-ai/ziran/blob/main/examples/07-cicd-quality-gate/Jenkinsfile)

---

## CircleCI

SARIF output is stored as a build artifact for download and inspection.

```yaml
version: 2.1

parameters:
  ziran-coverage:
    type: enum
    enum: ["essential", "standard", "comprehensive"]
    default: "standard"
  ziran-severity-threshold:
    type: enum
    enum: ["critical", "high", "medium", "low"]
    default: "medium"

jobs:
  ziran-security-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Install Ziran
          command: pip install ziran
      - run:
          name: Run security scan
          command: |
            ziran ci \
              --result-file ${RESULT_FILE:-scan_results.json} \
              --severity-threshold << pipeline.parameters.ziran-severity-threshold >> \
              --coverage << pipeline.parameters.ziran-coverage >> \
              --output sarif \
              --sarif-file ziran-results.sarif
      - store_artifacts:
          path: ziran-results.sarif
          destination: sarif-report

workflows:
  security:
    jobs:
      - ziran-security-scan
```

Full template: [`examples/07-cicd-quality-gate/circleci-config.yml`](https://github.com/taoq-ai/ziran/blob/main/examples/07-cicd-quality-gate/circleci-config.yml)

---

## Azure Pipelines

SARIF is published as a build artifact via `PublishBuildArtifacts`, making it available in the Azure DevOps pipeline summary.

```yaml
trigger:
  branches:
    include:
      - main

parameters:
  - name: ziranCoverage
    displayName: Coverage Level
    type: string
    default: standard
    values:
      - essential
      - standard
      - comprehensive
  - name: ziranSeverityThreshold
    displayName: Severity Threshold
    type: string
    default: medium
    values:
      - critical
      - high
      - medium
      - low

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
    displayName: Set up Python

  - script: pip install ziran
    displayName: Install Ziran

  - script: |
      ziran ci \
        --result-file ${RESULT_FILE:-scan_results.json} \
        --severity-threshold ${{ parameters.ziranSeverityThreshold }} \
        --coverage ${{ parameters.ziranCoverage }} \
        --output sarif \
        --sarif-file $(Build.ArtifactStagingDirectory)/ziran-results.sarif
    displayName: Run Ziran security scan

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)/ziran-results.sarif
      artifactName: CodeAnalysisLogs
    displayName: Upload SARIF report
    condition: always()
```

Full template: [`examples/07-cicd-quality-gate/azure-pipelines.yml`](https://github.com/taoq-ai/ziran/blob/main/examples/07-cicd-quality-gate/azure-pipelines.yml)

---

## See Also

- [CI/CD Integration Guide](cicd-integration.md) -- quality gate configuration, policy engine, SARIF details
- [CLI Reference](../reference/cli.md) -- all `ziran ci` flags
- [Example templates](https://github.com/taoq-ai/ziran/tree/main/examples/07-cicd-quality-gate)
