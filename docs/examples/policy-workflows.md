# Policy Workflow Examples

This guide provides real-world examples of integrating JMo Security Policy-as-Code into CI/CD pipelines and development workflows.

## Table of Contents

- [GitHub Actions](#github-actions)
  - [Basic Policy Gating](#basic-policy-gating-github-actions)
  - [Multi-Policy Enforcement](#multi-policy-enforcement-github-actions)
  - [PR Comment Automation](#pr-comment-automation)
- [GitLab CI](#gitlab-ci)
  - [Basic Policy Gating](#basic-policy-gating-gitlab-ci)
  - [Multi-Environment Policies](#multi-environment-policies-gitlab-ci)
  - [MR Policy Reports](#mr-policy-reports)
- [Jenkins](#jenkins)
  - [Declarative Pipeline](#declarative-pipeline-jenkins)
  - [Scripted Pipeline](#scripted-pipeline-jenkins)
- [Pre-Commit Hooks](#pre-commit-hooks)
- [Docker Compose](#docker-compose)
- [Kubernetes](#kubernetes)

---

## GitHub Actions

### Basic Policy Gating (GitHub Actions)

Fail CI/CD if secrets detected:

```yaml
name: Security Scan with Zero-Secrets Policy

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install OPA
        run: |
          wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
          chmod +x opa_linux_amd64
          sudo mv opa_linux_amd64 /usr/local/bin/opa

      - name: Install JMo Security
        run: pip install jmo-security

      - name: Run Security Scan
        run: |
          jmo ci \
            --repo . \
            --policy zero-secrets \
            --fail-on-policy-violation \
            --profile-name fast

      - name: Upload Policy Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: policy-results
          path: |
            results/summaries/POLICY_REPORT.md
            results/summaries/policy_results.json
```

### Multi-Policy Enforcement (GitHub Actions)

Enforce multiple policies based on branch:

```yaml
name: Multi-Policy Security Scan

on:
  push:
    branches: [main, develop, 'release/*']
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup OPA
        uses: open-policy-agent/setup-opa@v2
        with:
          version: '1.10.0'

      - name: Install JMo Security
        run: pip install jmo-security

      - name: Determine Policies (Main Branch)
        if: github.ref == 'refs/heads/main'
        run: echo "POLICIES=zero-secrets owasp-top-10 production-hardening" >> $GITHUB_ENV

      - name: Determine Policies (Develop Branch)
        if: github.ref == 'refs/heads/develop'
        run: echo "POLICIES=zero-secrets owasp-top-10" >> $GITHUB_ENV

      - name: Determine Policies (Pull Requests)
        if: github.event_name == 'pull_request'
        run: echo "POLICIES=zero-secrets" >> $GITHUB_ENV

      - name: Run Security Scan
        run: |
          jmo ci \
            --repo . \
            --policy $POLICIES \
            --fail-on-policy-violation \
            --profile-name balanced

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: policy-results-${{ github.sha }}
          path: results/summaries/
```

### PR Comment Automation

Post policy results as PR comments:

```yaml
name: Security Scan with PR Comment

on:
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Setup OPA
        uses: open-policy-agent/setup-opa@v2
        with:
          version: '1.10.0'

      - name: Install JMo Security
        run: pip install jmo-security

      - name: Run Security Scan
        id: scan
        continue-on-error: true
        run: |
          jmo ci \
            --repo . \
            --policy zero-secrets \
            --policy owasp-top-10 \
            --fail-on-policy-violation \
            --profile-name balanced

      - name: Post PR Comment
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');

            // Read policy report
            const policyReport = fs.readFileSync('results/summaries/POLICY_REPORT.md', 'utf8');

            // Post as PR comment
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔒 Security Policy Evaluation\n\n${policyReport}`
            });

      - name: Fail if policies failed
        if: steps.scan.outcome == 'failure'
        run: exit 1
```

---

## GitLab CI

### Basic Policy Gating (GitLab CI)

```yaml
security-scan:
  stage: test
  image: python:3.11

  before_script:
    - pip install jmo-security
    - wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
    - chmod +x opa_linux_amd64
    - mv opa_linux_amd64 /usr/local/bin/opa

  script:
    - |
      jmo ci \
        --repo . \
        --policy zero-secrets \
        --policy owasp-top-10 \
        --fail-on-policy-violation \
        --profile-name balanced

  artifacts:
    when: always
    paths:
      - results/summaries/
    reports:
      junit: results/summaries/policy_results.json
    expire_in: 30 days

  only:
    - merge_requests
    - main
    - develop
```

### Multi-Environment Policies (GitLab CI)

Different policies for different environments:

```yaml
variables:
  POLICY_DEVELOP: "zero-secrets"
  POLICY_STAGING: "zero-secrets owasp-top-10"
  POLICY_PRODUCTION: "zero-secrets owasp-top-10 production-hardening pci-dss"

.scan_template: &scan_template
  image: python:3.11
  before_script:
    - pip install jmo-security
    - wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
    - chmod +x opa_linux_amd64
    - mv opa_linux_amd64 /usr/local/bin/opa
  artifacts:
    when: always
    paths:
      - results/summaries/
    expire_in: 30 days

security-scan-develop:
  <<: *scan_template
  stage: test
  script:
    - jmo ci --repo . --policy $POLICY_DEVELOP --fail-on-policy-violation
  only:
    - develop

security-scan-staging:
  <<: *scan_template
  stage: test
  script:
    - jmo ci --repo . --policy $POLICY_STAGING --fail-on-policy-violation
  only:
    - staging

security-scan-production:
  <<: *scan_template
  stage: test
  script:
    - jmo ci --repo . --policy $POLICY_PRODUCTION --fail-on-policy-violation
  only:
    - main
    - tags
```

### MR Policy Reports

Post policy results to merge request notes:

```yaml
security-scan:
  stage: test
  image: python:3.11

  before_script:
    - pip install jmo-security python-gitlab
    - wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
    - chmod +x opa_linux_amd64
    - mv opa_linux_amd64 /usr/local/bin/opa

  script:
    - |
      # Run scan
      jmo ci \
        --repo . \
        --policy zero-secrets \
        --policy owasp-top-10 \
        --fail-on-policy-violation || true

      # Post to MR
      if [ -f results/summaries/POLICY_REPORT.md ]; then
        python3 - <<'EOF'
import gitlab
import os

gl = gitlab.Gitlab(os.environ['CI_SERVER_URL'], private_token=os.environ['GITLAB_TOKEN'])
project = gl.projects.get(os.environ['CI_PROJECT_ID'])
mr = project.mergerequests.get(os.environ['CI_MERGE_REQUEST_IID'])

with open('results/summaries/POLICY_REPORT.md', 'r') as f:
    report = f.read()

mr.notes.create({'body': f'## 🔒 Security Policy Evaluation\n\n{report}'})
EOF
      fi

  artifacts:
    when: always
    paths:
      - results/summaries/

  only:
    - merge_requests
```

---

## Jenkins

### Declarative Pipeline (Jenkins)

```groovy
pipeline {
    agent any

    environment {
        OPA_VERSION = '1.10.0'
    }

    stages {
        stage('Setup') {
            steps {
                sh '''
                    # Install OPA
                    wget https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64
                    chmod +x opa_linux_amd64
                    sudo mv opa_linux_amd64 /usr/local/bin/opa

                    # Install JMo Security
                    pip install jmo-security
                '''
            }
        }

        stage('Security Scan') {
            steps {
                script {
                    def policies = []

                    // Branch-specific policies
                    if (env.BRANCH_NAME == 'main') {
                        policies = ['zero-secrets', 'owasp-top-10', 'production-hardening']
                    } else if (env.BRANCH_NAME == 'develop') {
                        policies = ['zero-secrets', 'owasp-top-10']
                    } else {
                        policies = ['zero-secrets']
                    }

                    def policyArgs = policies.collect { "--policy $it" }.join(' ')

                    sh """
                        jmo ci \
                          --repo . \
                          ${policyArgs} \
                          --fail-on-policy-violation \
                          --profile-name balanced
                    """
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'results/summaries/*', fingerprint: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'results/summaries',
                reportFiles: 'POLICY_REPORT.md',
                reportName: 'Policy Report'
            ])
        }
    }
}
```

### Scripted Pipeline (Jenkins)

```groovy
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Setup') {
        sh '''
            wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
            chmod +x opa_linux_amd64
            sudo mv opa_linux_amd64 /usr/local/bin/opa
            pip install jmo-security
        '''
    }

    stage('Security Scan') {
        try {
            sh '''
                jmo ci \
                  --repo . \
                  --policy zero-secrets \
                  --policy owasp-top-10 \
                  --fail-on-policy-violation \
                  --profile-name balanced
            '''
        } catch (Exception e) {
            currentBuild.result = 'FAILURE'
            error("Policy violations detected: ${e.message}")
        }
    }

    stage('Archive Results') {
        archiveArtifacts artifacts: 'results/summaries/*', fingerprint: true
    }
}
```

---

## Pre-Commit Hooks

### Local Pre-Commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

echo "🔒 Running security policy check..."

# Run JMo scan with zero-secrets policy
jmo ci \
  --repo . \
  --policy zero-secrets \
  --fail-on-policy-violation \
  --profile-name fast

if [ $? -ne 0 ]; then
  echo "❌ COMMIT BLOCKED: Security policy violations detected"
  echo "📋 View report: results/summaries/POLICY_REPORT.md"
  exit 1
fi

echo "✅ Security policy check passed"
exit 0
```

Make executable:

```bash
chmod +x .git/hooks/pre-commit
```

### Pre-Commit Framework Integration

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: jmo-security-scan
        name: JMo Security Scan
        entry: bash -c 'jmo ci --repo . --policy zero-secrets --fail-on-policy-violation --profile-name fast'
        language: system
        pass_filenames: false
        always_run: true
```

Install hook:

```bash
pre-commit install
```

---

## Docker Compose

### Policy Gating in Docker Compose

```yaml
version: '3.8'

services:
  jmo-security-scan:
    image: jmo-security:latest
    volumes:
      - .:/scan
      - ./results:/results
    environment:
      - JMO_POLICY_ENABLED=true
      - JMO_POLICY_DEFAULT_POLICIES=zero-secrets,owasp-top-10
      - JMO_POLICY_FAIL_ON_VIOLATION=true
    command: |
      bash -c "
        jmo ci \
          --repo /scan \
          --policy zero-secrets \
          --policy owasp-top-10 \
          --fail-on-policy-violation \
          --profile-name balanced
      "
```

Run:

```bash
docker-compose up jmo-security-scan
```

---

## Kubernetes

### Kubernetes Job for Policy Scanning

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: jmo-security-scan
  namespace: ci-cd
spec:
  template:
    metadata:
      labels:
        app: jmo-security
    spec:
      restartPolicy: Never
      containers:
        - name: scanner
          image: jmo-security:latest
          env:
            - name: JMO_POLICY_ENABLED
              value: "true"
            - name: JMO_POLICY_DEFAULT_POLICIES
              value: "zero-secrets,owasp-top-10,production-hardening"
            - name: JMO_POLICY_FAIL_ON_VIOLATION
              value: "true"
          command:
            - /bin/bash
            - -c
            - |
              jmo ci \
                --repo /scan \
                --policy zero-secrets \
                --policy owasp-top-10 \
                --policy production-hardening \
                --fail-on-policy-violation \
                --profile-name balanced
          volumeMounts:
            - name: source-code
              mountPath: /scan
            - name: results
              mountPath: /results
      volumes:
        - name: source-code
          gitRepo:
            repository: https://github.com/your-org/your-repo.git
            revision: main
        - name: results
          persistentVolumeClaim:
            claimName: jmo-results-pvc
```

---

## Additional Resources

- [Policy-as-Code Guide](../POLICY_AS_CODE.md)
- [Custom Policy Examples](custom-policy-examples.md)
- [JMo User Guide](../USER_GUIDE.md)
- [Docker README](../DOCKER_README.md)

---

## Support

- **GitHub Issues:** [jmo-security-repo/issues](https://github.com/jimmy058910/jmo-security-repo/issues)
- **Community Forum:** [GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)
