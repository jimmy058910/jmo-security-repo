# CI/CD Integration with Trend Analysis

This guide demonstrates how to integrate JMo Security trend analysis into various CI/CD platforms for continuous security monitoring.

## Table of Contents

- [Overview](#overview)
- [GitHub Actions](#github-actions)
  - [Basic Workflow](#basic-workflow)
  - [Multi-Branch Strategy](#multi-branch-strategy)
  - [Regression Gating](#regression-gating)
  - [Scheduled Audits](#scheduled-audits)
- [GitLab CI](#gitlab-ci)
  - [Basic Pipeline](#basic-pipeline)
  - [Merge Request Integration](#merge-request-integration)
  - [Environment-Specific Scans](#environment-specific-scans)
- [Jenkins](#jenkins)
  - [Declarative Pipeline](#declarative-pipeline)
  - [Scripted Pipeline](#scripted-pipeline)
  - [Multibranch Pipeline](#multibranch-pipeline)
- [Azure Pipelines](#azure-pipelines)
- [CircleCI](#circleci)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

Trend analysis in CI/CD enables:

- **Regression detection** - Block deployments with new HIGH/CRITICAL findings
- **Historical tracking** - Build security posture trends over time
- **Developer accountability** - Identify who introduced security issues
- **Compliance reporting** - Generate audit-ready trend reports

**Key Requirements:**

1. **History database persistence** - Use caching or artifacts to preserve `.jmo/history.db`
2. **Git history access** - Mount `.git` directory (read-only) for developer attribution
3. **Branch isolation** - Separate trend data by branch to avoid contamination

---

## GitHub Actions

### Basic Workflow

Scan on every push with trend analysis:

```yaml
name: Security Scan with Trends

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git blame

      # Restore history database from cache
      - name: Restore JMo history cache
        uses: actions/cache@v4
        with:
          path: .jmo
          key: jmo-history-${{ github.repository }}-${{ github.ref_name }}
          restore-keys: |
            jmo-history-${{ github.repository }}-

      # Run security scan
      - name: Run JMo Security scan
        run: |
          mkdir -p .jmo
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            scan --repo /scan --results-dir /scan/results --profile-name balanced

      # Analyze trends
      - name: Analyze security trends
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends analyze --branch ${{ github.ref_name }} --format terminal

      # Check for regressions (fail build if new HIGH/CRITICAL)
      - name: Check for regressions
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends regressions --severity HIGH --format terminal

      # Export trend report
      - name: Export trend report
        if: always()
        run: |
          mkdir -p reports
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            -v ${{ github.workspace }}/reports:/reports \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends analyze --export html --export-file /reports/trends-report.html

      # Upload reports as artifacts
      - name: Upload trend report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-trends-${{ github.ref_name }}
          path: reports/trends-report.html
          retention-days: 30
```

**Key Features:**

- Branch-specific cache keys for isolated trend data
- Full git history with `fetch-depth: 0`
- Regression gating with `--severity HIGH`
- HTML report generation and artifact upload

### Multi-Branch Strategy

Track trends separately for `main`, `develop`, and feature branches:

```yaml
name: Multi-Branch Security Trends

on:
  push:
    branches: ['**']  # All branches
  pull_request:
    branches: [main, develop]

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Branch-specific cache
      - name: Restore history cache
        uses: actions/cache@v4
        with:
          path: .jmo
          key: jmo-${{ github.repository }}-${{ github.ref_name }}-${{ hashFiles('**/*.py', '**/*.js') }}
          restore-keys: |
            jmo-${{ github.repository }}-${{ github.ref_name }}-
            jmo-${{ github.repository }}-

      - name: Run scan
        run: |
          mkdir -p .jmo
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            scan --repo /scan --results-dir /scan/results --profile-name balanced

      # Analyze with branch context
      - name: Analyze trends
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends analyze --branch ${{ github.ref_name }} --scans 10 --format terminal

      # Compare against main branch baseline
      - name: Compare with main branch
        if: github.ref != 'refs/heads/main'
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends score --branch ${{ github.ref_name }} --format terminal
```

**Cache Strategy:**

- **Primary key:** `jmo-{repo}-{branch}-{hash}` (changes invalidate cache)
- **Restore keys:** Fallback to branch cache, then repo cache
- **Benefit:** Prevents cross-contamination between branches

### Regression Gating

Block deployments if security trends worsen:

```yaml
name: Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Restore history
        uses: actions/cache@v4
        with:
          path: .jmo
          key: jmo-history-${{ github.repository }}-main

      - name: Run scan
        run: |
          mkdir -p .jmo
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            scan --repo /scan --results-dir /scan/results --profile-name balanced

      # CRITICAL: Fail if HIGH/CRITICAL regressions detected
      - name: Regression gate
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends regressions --severity HIGH --format terminal
        continue-on-error: false  # Fail build on regressions

      # Calculate security score (informational)
      - name: Security score
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends score --branch main --scans 5 --format terminal

      # Post results to PR
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const score = fs.readFileSync('score.txt', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔒 Security Trends\n\n${score}`
            });
```

**Deployment Gate Logic:**

1. Run security scan
2. Check regressions with `trends regressions`
3. **FAIL build** if new HIGH/CRITICAL findings
4. Calculate security score (informational)
5. Post results to PR (optional)

### Scheduled Audits

Weekly trend analysis for compliance reporting:

```yaml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 2 * * 1'  # Every Monday at 2 AM UTC
  workflow_dispatch:  # Manual trigger

jobs:
  audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Restore history
        uses: actions/cache@v4
        with:
          path: .jmo
          key: jmo-history-${{ github.repository }}-main

      - name: Run comprehensive scan
        run: |
          mkdir -p .jmo reports
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            scan --repo /scan --results-dir /scan/results --profile-name deep

      # Generate comprehensive trend analysis
      - name: Generate trend report
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            -v ${{ github.workspace }}/reports:/reports \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends analyze --branch main --scans 52 --export html --export-file /reports/weekly-audit.html

      # Export for monitoring systems
      - name: Export Prometheus metrics
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            -v ${{ github.workspace }}/reports:/reports \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends analyze --export prometheus --export-file /reports/metrics.prom

      # Developer attribution report
      - name: Developer impact analysis
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/.git:/scan/.git:ro \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            -v ${{ github.workspace }}/reports:/reports \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends developers --branch main --format json > reports/developers.json

      # Upload comprehensive audit package
      - name: Upload audit reports
        uses: actions/upload-artifact@v4
        with:
          name: weekly-security-audit-${{ github.run_number }}
          path: reports/
          retention-days: 365  # Keep for 1 year (compliance)
```

**Audit Features:**

- Weekly schedule (adjustable)
- Deep profile scan (comprehensive)
- 52-week trend analysis (1 year)
- Prometheus metrics export
- Developer attribution
- 365-day artifact retention

---

## GitLab CI

### Basic Pipeline

`.gitlab-ci.yml`:

```yaml
stages:
  - scan
  - analyze

variables:
  DOCKER_DRIVER: overlay2
  JMO_IMAGE: ghcr.io/jimmy058910/jmo-security:latest

security-scan:
  stage: scan
  image: docker:latest
  services:
    - docker:dind
  cache:
    key: jmo-history-${CI_PROJECT_ID}-${CI_COMMIT_REF_NAME}
    paths:
      - .jmo/
  script:
    - mkdir -p .jmo
    # Run scan
    - |
      docker run --rm \
        -v $PWD:/scan \
        -v $PWD/.jmo:/root/.jmo \
        $JMO_IMAGE \
        scan --repo /scan --results-dir /scan/results --profile-name balanced
  artifacts:
    paths:
      - results/
    expire_in: 30 days

trend-analysis:
  stage: analyze
  image: docker:latest
  services:
    - docker:dind
  dependencies:
    - security-scan
  cache:
    key: jmo-history-${CI_PROJECT_ID}-${CI_COMMIT_REF_NAME}
    paths:
      - .jmo/
    policy: pull  # Read-only
  script:
    # Analyze trends
    - |
      docker run --rm \
        -v $PWD/.jmo:/root/.jmo \
        $JMO_IMAGE \
        trends analyze --branch ${CI_COMMIT_REF_NAME} --format terminal
    # Check regressions
    - |
      docker run --rm \
        -v $PWD/.jmo:/root/.jmo \
        $JMO_IMAGE \
        trends regressions --severity HIGH --format terminal
    # Export HTML report
    - mkdir -p reports
    - |
      docker run --rm \
        -v $PWD/.jmo:/root/.jmo \
        -v $PWD/reports:/reports \
        $JMO_IMAGE \
        trends analyze --export html --export-file /reports/trends.html
  artifacts:
    paths:
      - reports/trends.html
    expire_in: 90 days
```

**GitLab Features:**

- Two-stage pipeline (scan → analyze)
- Project-specific cache keys
- DinD (Docker-in-Docker) for nested containers
- 90-day trend report retention

### Merge Request Integration

Add MR-specific trend analysis:

```yaml
mr-security-check:
  stage: analyze
  image: docker:latest
  services:
    - docker:dind
  only:
    - merge_requests
  cache:
    key: jmo-history-${CI_PROJECT_ID}-${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}
    paths:
      - .jmo/
    policy: pull
  script:
    # Compare MR branch vs target branch
    - |
      docker run --rm \
        -v $PWD/.jmo:/root/.jmo \
        $JMO_IMAGE \
        trends score --branch ${CI_COMMIT_REF_NAME} --format terminal
    # Post results to MR (requires GitLab API token)
    - |
      SCORE=$(docker run --rm -v $PWD/.jmo:/root/.jmo $JMO_IMAGE \
        trends score --branch ${CI_COMMIT_REF_NAME} --format json | jq -r '.score')
      curl -X POST \
        "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests/${CI_MERGE_REQUEST_IID}/notes" \
        -H "PRIVATE-TOKEN: ${GITLAB_API_TOKEN}" \
        -d "body=Security Score: ${SCORE}/100"
```

### Environment-Specific Scans

Track trends per environment (dev/staging/prod):

```yaml
.scan_template: &scan_template
  stage: scan
  image: docker:latest
  services:
    - docker:dind
  script:
    - mkdir -p .jmo
    - |
      docker run --rm \
        -v $PWD:/scan \
        -v $PWD/.jmo:/root/.jmo \
        ghcr.io/jimmy058910/jmo-security:latest \
        scan --repo /scan --results-dir /scan/results-${ENVIRONMENT} --profile-name balanced
    - |
      docker run --rm \
        -v $PWD/.jmo:/root/.jmo \
        ghcr.io/jimmy058910/jmo-security:latest \
        trends analyze --branch ${CI_COMMIT_REF_NAME}-${ENVIRONMENT} --format terminal

scan-dev:
  <<: *scan_template
  variables:
    ENVIRONMENT: dev
  cache:
    key: jmo-${CI_PROJECT_ID}-dev
    paths:
      - .jmo/
  only:
    - develop

scan-staging:
  <<: *scan_template
  variables:
    ENVIRONMENT: staging
  cache:
    key: jmo-${CI_PROJECT_ID}-staging
    paths:
      - .jmo/
  only:
    - staging

scan-prod:
  <<: *scan_template
  variables:
    ENVIRONMENT: prod
  cache:
    key: jmo-${CI_PROJECT_ID}-prod
    paths:
      - .jmo/
  only:
    - main
```

---

## Jenkins

### Declarative Pipeline

`Jenkinsfile`:

```groovy
pipeline {
    agent any

    environment {
        JMO_IMAGE = 'ghcr.io/jimmy058910/jmo-security:latest'
        JMO_CACHE = "${WORKSPACE}/.jmo"
    }

    stages {
        stage('Restore History') {
            steps {
                script {
                    // Restore from Jenkins workspace cache
                    sh "mkdir -p ${JMO_CACHE}"
                }
            }
        }

        stage('Security Scan') {
            steps {
                sh """
                    docker run --rm \
                        -v ${WORKSPACE}:/scan \
                        -v ${JMO_CACHE}:/root/.jmo \
                        ${JMO_IMAGE} \
                        scan --repo /scan --results-dir /scan/results --profile-name balanced
                """
            }
        }

        stage('Trend Analysis') {
            steps {
                sh """
                    docker run --rm \
                        -v ${JMO_CACHE}:/root/.jmo \
                        ${JMO_IMAGE} \
                        trends analyze --branch ${BRANCH_NAME} --format terminal
                """
            }
        }

        stage('Regression Check') {
            steps {
                script {
                    def exitCode = sh(
                        script: """
                            docker run --rm \
                                -v ${JMO_CACHE}:/root/.jmo \
                                ${JMO_IMAGE} \
                                trends regressions --severity HIGH --format terminal
                        """,
                        returnStatus: true
                    )
                    if (exitCode != 0) {
                        error("Security regressions detected!")
                    }
                }
            }
        }

        stage('Generate Report') {
            steps {
                sh """
                    mkdir -p reports
                    docker run --rm \
                        -v ${JMO_CACHE}:/root/.jmo \
                        -v ${WORKSPACE}/reports:/reports \
                        ${JMO_IMAGE} \
                        trends analyze --export html --export-file /reports/trends.html
                """
            }
        }
    }

    post {
        always {
            // Archive trend report
            archiveArtifacts artifacts: 'reports/trends.html', allowEmptyArchive: true

            // Publish HTML report
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: 'trends.html',
                reportName: 'Security Trends'
            ])
        }
    }
}
```

### Scripted Pipeline

For complex workflows:

```groovy
node {
    def jmoImage = 'ghcr.io/jimmy058910/jmo-security:latest'
    def jmoCache = "${WORKSPACE}/.jmo"

    stage('Checkout') {
        checkout scm
    }

    stage('Restore Cache') {
        sh "mkdir -p ${jmoCache}"
    }

    stage('Security Scan') {
        docker.image(jmoImage).inside("-v ${WORKSPACE}:/scan -v ${jmoCache}:/root/.jmo") {
            sh "jmo scan --repo /scan --results-dir /scan/results --profile-name balanced"
        }
    }

    stage('Trend Analysis') {
        docker.image(jmoImage).inside("-v ${jmoCache}:/root/.jmo") {
            sh "jmo trends analyze --branch ${BRANCH_NAME} --format terminal"
        }
    }

    stage('Check Regressions') {
        try {
            docker.image(jmoImage).inside("-v ${jmoCache}:/root/.jmo") {
                sh "jmo trends regressions --severity HIGH --format terminal"
            }
        } catch (Exception e) {
            currentBuild.result = 'FAILURE'
            error("Security regressions detected: ${e.message}")
        }
    }

    stage('Export Reports') {
        sh "mkdir -p reports"
        docker.image(jmoImage).inside("-v ${jmoCache}:/root/.jmo -v ${WORKSPACE}/reports:/reports") {
            sh "jmo trends analyze --export html --export-file /reports/trends.html"
            sh "jmo trends analyze --export prometheus --export-file /reports/metrics.prom"
        }
    }

    stage('Publish') {
        archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: 'reports',
            reportFiles: 'trends.html',
            reportName: 'Security Trends'
        ])
    }
}
```

### Multibranch Pipeline

Track trends per branch automatically:

```groovy
pipeline {
    agent any

    environment {
        JMO_IMAGE = 'ghcr.io/jimmy058910/jmo-security:latest'
        JMO_CACHE = "${JENKINS_HOME}/jmo-cache/${JOB_NAME}/${BRANCH_NAME}"
    }

    stages {
        stage('Setup') {
            steps {
                sh "mkdir -p ${JMO_CACHE}"
            }
        }

        stage('Scan') {
            steps {
                sh """
                    docker run --rm \
                        -v ${WORKSPACE}:/scan \
                        -v ${JMO_CACHE}:/root/.jmo \
                        ${JMO_IMAGE} \
                        scan --repo /scan --results-dir /scan/results --profile-name balanced
                """
            }
        }

        stage('Analyze') {
            steps {
                sh """
                    docker run --rm \
                        -v ${JMO_CACHE}:/root/.jmo \
                        ${JMO_IMAGE} \
                        trends analyze --branch ${BRANCH_NAME} --scans 10 --format terminal
                """
            }
        }

        stage('Compare with Main') {
            when {
                not { branch 'main' }
            }
            steps {
                sh """
                    docker run --rm \
                        -v ${JMO_CACHE}:/root/.jmo \
                        ${JMO_IMAGE} \
                        trends score --branch ${BRANCH_NAME} --format terminal
                """
            }
        }
    }

    post {
        always {
            sh """
                mkdir -p reports
                docker run --rm \
                    -v ${JMO_CACHE}:/root/.jmo \
                    -v ${WORKSPACE}/reports:/reports \
                    ${JMO_IMAGE} \
                    trends analyze --export html --export-file /reports/trends-${BRANCH_NAME}.html
            """
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
```

---

## Azure Pipelines

`azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  JMO_IMAGE: 'ghcr.io/jimmy058910/jmo-security:latest'
  JMO_CACHE: '$(Pipeline.Workspace)/.jmo'

steps:
  # Restore history cache
  - task: Cache@2
    inputs:
      key: 'jmo-history | "$(Build.Repository.Name)" | "$(Build.SourceBranchName)"'
      path: $(JMO_CACHE)
    displayName: 'Restore JMo history cache'

  # Checkout repository
  - checkout: self
    fetchDepth: 0  # Full history for git blame

  # Run security scan
  - script: |
      mkdir -p $(JMO_CACHE)
      docker run --rm \
        -v $(Build.SourcesDirectory):/scan \
        -v $(JMO_CACHE):/root/.jmo \
        $(JMO_IMAGE) \
        scan --repo /scan --results-dir /scan/results --profile-name balanced
    displayName: 'Run security scan'

  # Analyze trends
  - script: |
      docker run --rm \
        -v $(JMO_CACHE):/root/.jmo \
        $(JMO_IMAGE) \
        trends analyze --branch $(Build.SourceBranchName) --format terminal
    displayName: 'Analyze security trends'

  # Check regressions
  - script: |
      docker run --rm \
        -v $(JMO_CACHE):/root/.jmo \
        $(JMO_IMAGE) \
        trends regressions --severity HIGH --format terminal
    displayName: 'Check for regressions'
    continueOnError: false

  # Export trend report
  - script: |
      mkdir -p $(Build.ArtifactStagingDirectory)/reports
      docker run --rm \
        -v $(JMO_CACHE):/root/.jmo \
        -v $(Build.ArtifactStagingDirectory)/reports:/reports \
        $(JMO_IMAGE) \
        trends analyze --export html --export-file /reports/trends.html
    displayName: 'Generate trend report'
    condition: always()

  # Publish reports
  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)/reports'
      ArtifactName: 'security-trends'
      publishLocation: 'Container'
    displayName: 'Publish trend report'
    condition: always()
```

---

## CircleCI

`.circleci/config.yml`:

```yaml
version: 2.1

executors:
  docker-executor:
    docker:
      - image: docker:latest
    working_directory: /workspace

jobs:
  security-scan:
    executor: docker-executor
    steps:
      - checkout
      - setup_remote_docker

      # Restore history cache
      - restore_cache:
          keys:
            - jmo-history-{{ .Branch }}-{{ checksum "requirements.txt" }}
            - jmo-history-{{ .Branch }}-
            - jmo-history-

      # Run scan
      - run:
          name: Run security scan
          command: |
            mkdir -p .jmo
            docker run --rm \
              -v $(pwd):/scan \
              -v $(pwd)/.jmo:/root/.jmo \
              ghcr.io/jimmy058910/jmo-security:latest \
              scan --repo /scan --results-dir /scan/results --profile-name balanced

      # Analyze trends
      - run:
          name: Analyze trends
          command: |
            docker run --rm \
              -v $(pwd)/.jmo:/root/.jmo \
              ghcr.io/jimmy058910/jmo-security:latest \
              trends analyze --branch ${CIRCLE_BRANCH} --format terminal

      # Check regressions
      - run:
          name: Check regressions
          command: |
            docker run --rm \
              -v $(pwd)/.jmo:/root/.jmo \
              ghcr.io/jimmy058910/jmo-security:latest \
              trends regressions --severity HIGH --format terminal

      # Export report
      - run:
          name: Generate trend report
          command: |
            mkdir -p reports
            docker run --rm \
              -v $(pwd)/.jmo:/root/.jmo \
              -v $(pwd)/reports:/reports \
              ghcr.io/jimmy058910/jmo-security:latest \
              trends analyze --export html --export-file /reports/trends.html
          when: always

      # Save cache
      - save_cache:
          key: jmo-history-{{ .Branch }}-{{ checksum "requirements.txt" }}
          paths:
            - .jmo

      # Store artifacts
      - store_artifacts:
          path: reports/trends.html
          destination: security-trends

workflows:
  security:
    jobs:
      - security-scan:
          filters:
            branches:
              only:
                - main
                - develop
```

---

## Best Practices

### 1. Branch Isolation

**Problem:** Cross-contamination of trend data between branches

**Solution:** Use branch-specific cache keys

```yaml
# GitHub Actions
cache:
  key: jmo-history-${{ github.repository }}-${{ github.ref_name }}

# GitLab CI
cache:
  key: jmo-history-${CI_PROJECT_ID}-${CI_COMMIT_REF_NAME}

# Jenkins
JMO_CACHE = "${JENKINS_HOME}/jmo-cache/${JOB_NAME}/${BRANCH_NAME}"
```

### 2. Git History for Developer Attribution

**Problem:** Cannot attribute findings to developers without git history

**Solution:** Mount `.git` directory (read-only for safety)

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  -v "$(pwd)/.git:/scan/.git:ro" \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends developers --limit 10
```

### 3. Cache Invalidation Strategy

**Option 1: Time-based (recommended for main branch)**

```yaml
# Invalidate cache weekly (force fresh baseline)
key: jmo-history-main-${{ github.run_number }}-week-${{ format('{0:yyyyMMdd}', pipeline.startTime) / 7 }}
```

**Option 2: Content-based (recommended for feature branches)**

```yaml
# Invalidate when code changes
key: jmo-history-${{ github.ref_name }}-${{ hashFiles('**/*.py', '**/*.js') }}
```

**Option 3: Manual invalidation**

```bash
# Delete cache from CI platform UI or API
gh cache delete jmo-history-main  # GitHub CLI
```

### 4. Regression Severity Thresholds

**Recommended thresholds by environment:**

- **Production deployments:** `--severity HIGH` (block HIGH/CRITICAL)
- **Staging deployments:** `--severity MEDIUM` (warn on MEDIUM+)
- **Development branches:** No gating (informational only)

```yaml
# Production
trends regressions --severity HIGH --format terminal

# Staging
trends regressions --severity MEDIUM --format terminal || true

# Development
trends regressions --format terminal || true  # Never fail
```

### 5. Artifact Retention

**Retention guidelines:**

- **Compliance audits:** 365+ days (1 year minimum)
- **Release branches:** 90 days
- **Feature branches:** 30 days
- **PR branches:** 7 days

```yaml
# GitHub Actions
retention-days: 365  # Compliance

# GitLab CI
expire_in: 90 days  # Release branches

# Jenkins
archiveArtifacts artifacts: 'reports/**', daysToKeepStr: '30'
```

### 6. Export to Monitoring Systems

**Integrate with observability platforms:**

```bash
# Prometheus metrics
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  -v $(pwd)/metrics:/metrics \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends analyze --export prometheus --export-file /metrics/jmo.prom

# Push to Pushgateway
curl -X POST http://pushgateway:9091/metrics/job/jmo-security < metrics/jmo.prom
```

**Grafana dashboard import:**

```bash
# Generate Grafana-compatible JSON
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  -v $(pwd)/dashboards:/dashboards \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends analyze --export grafana --export-file /dashboards/jmo.json

# Import via Grafana API
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -H "Content-Type: application/json" \
  -d @dashboards/jmo.json
```

---

## Troubleshooting

### Cache Not Persisting

**Symptoms:** "No scans found in history database" on every run

**Causes:**

1. **Cache key mismatch** - Changing cache key invalidates history
2. **Cache size limit** - Some platforms have cache size limits
3. **Permission issues** - Container can't write to cache directory

**Solutions:**

1. **Verify cache key consistency:**

   ```yaml
   # Use stable cache key without volatile data
   key: jmo-history-${{ github.repository }}-${{ github.ref_name }}
   # NOT: jmo-history-${{ github.run_number }}  # Changes every run!
   ```

2. **Check cache size:**

   ```bash
   # GitHub Actions: Check cache size (max 10 GB per repo)
   gh cache list

   # Compress history database if needed
   gzip .jmo/history.db
   ```

3. **Fix permissions:**

   ```bash
   # Ensure cache directory is writable
   mkdir -p .jmo
   chmod 755 .jmo
   ```

### Trends Not Showing Statistical Significance

**Symptoms:** "No significant trends detected" despite multiple scans

**Causes:**

1. **Insufficient scan history** - Need ≥5 scans for Mann-Kendall test
2. **No actual trend** - Data is stable (not improving/worsening)
3. **High variability** - Noisy data obscures trends

**Solutions:**

1. **Check scan count:**

   ```bash
   docker run --rm -v ~/.jmo:/root/.jmo \
     ghcr.io/jimmy058910/jmo-security:latest \
     trends show --format terminal
   # Output: "10 scans in history for branch 'main'"
   ```

2. **Lower p-value threshold (use with caution):**

   ```bash
   # Default: p < 0.05 (95% confidence)
   # More sensitive: p < 0.10 (90% confidence)
   # NOTE: Not configurable in v1.0.0, use insights for interpretation
   ```

3. **Analyze insights:**

   ```bash
   docker run --rm -v ~/.jmo:/root/.jmo \
     ghcr.io/jimmy058910/jmo-security:latest \
     trends insights --branch main --format terminal
   ```

### Regression False Positives

**Symptoms:** Build fails on "regressions" that aren't real issues

**Causes:**

1. **Tool version changes** - Different tool versions find different issues
2. **Scan profile changes** - Switching from fast → balanced adds tools
3. **Codebase growth** - More code = more findings (not a regression)

**Solutions:**

1. **Baseline reset after tool updates:**

   ```bash
   # Delete history after upgrading tools
   rm .jmo/history.db

   # Or use branch-specific baseline
   docker run --rm -v ~/.jmo:/root/.jmo \
     ghcr.io/jimmy058910/jmo-security:latest \
     trends analyze --branch main-v2.0 --format terminal
   ```

2. **Use consistent scan profiles:**

   ```bash
   # Always use same profile for trend analysis
   docker run --rm \
     -v $(pwd):/scan \
     -v ~/.jmo:/root/.jmo \
     ghcr.io/jimmy058910/jmo-security:latest \
     scan --repo /scan --profile-name balanced
   ```

3. **Normalize by codebase size:**

   ```bash
   # Calculate findings per 1000 lines of code
   LOC=$(cloc --json . | jq -r '.SUM.code')
   FINDINGS=$(jq '.findings | length' results/summaries/findings.json)
   NORMALIZED=$(echo "scale=2; $FINDINGS * 1000 / $LOC" | bc)
   echo "Findings per 1000 LOC: $NORMALIZED"
   ```

### Developer Attribution Not Working

**Symptoms:** "Git repository not found" or "No git blame data"

**Causes:**

1. **`.git` directory not mounted**
2. **Shallow clone** - `fetch-depth: 1` doesn't include full history
3. **Detached HEAD** - CI checkouts often use commit SHA

**Solutions:**

1. **Mount `.git` directory:**

   ```yaml
   # GitHub Actions
   - run: |
       docker run --rm \
         -v ${{ github.workspace }}:/scan \
         -v ${{ github.workspace }}/.git:/scan/.git:ro \
         -v ${{ github.workspace }}/.jmo:/root/.jmo \
         ghcr.io/jimmy058910/jmo-security:latest \
         trends developers --limit 10
   ```

2. **Fetch full history:**

   ```yaml
   # GitHub Actions
   - uses: actions/checkout@v4
     with:
       fetch-depth: 0  # Full history (not shallow clone)
   ```

3. **Checkout branch (not commit):**

   ```yaml
   # GitHub Actions
   - uses: actions/checkout@v4
     with:
       ref: ${{ github.head_ref }}  # Branch name, not SHA
   ```

### CI Timeout on Large Repositories

**Symptoms:** CI job times out during trend analysis

**Causes:**

1. **Large history database** - 100+ scans with millions of findings
2. **Developer attribution** - Git blame on large repos is slow
3. **Export formats** - HTML generation with embedded data

**Solutions:**

1. **Limit scan window:**

   ```bash
   # Analyze last 20 scans only (not all history)
   docker run --rm -v ~/.jmo:/root/.jmo \
     ghcr.io/jimmy058910/jmo-security:latest \
     trends analyze --scans 20 --format terminal
   ```

2. **Skip developer attribution in CI:**

   ```bash
   # Run attribution separately (scheduled job, not every commit)
   # See "Scheduled Audits" example above
   ```

3. **Use lightweight exports:**

   ```bash
   # JSON export is fastest (no HTML rendering)
   docker run --rm -v ~/.jmo:/root/.jmo -v $(pwd)/reports:/reports \
     ghcr.io/jimmy058910/jmo-security:latest \
     trends analyze --export json --export-file /reports/trends.json
   ```

---

## Additional Resources

- **Main Documentation:** [README.md](../../README.md)
- **User Guide:** [USER_GUIDE.md](../USER_GUIDE.md)
- **Docker Guide:** [DOCKER_README.md](../DOCKER_README.md)
- **Quick Start:** [QUICKSTART.md](../../QUICKSTART.md)
- **API Reference:** [API_REFERENCE.md](../API_REFERENCE.md)
- **Wizard Examples:** [wizard-examples.md](wizard-examples.md)
