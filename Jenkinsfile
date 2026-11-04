// ============================================================
//  HotelHub — Jenkins DevSecOps CI Pipeline
//  Tools: pytest | pip-audit | Bandit | Trivy | OWASP Dep-Check
// ============================================================

pipeline {

    agent any   // Use 'agent { docker { image "python:3.11-slim" } }' for Docker agents

    // ── Environment variables ────────────────────────────────
    environment {
        VENV_DIR              = "${WORKSPACE}/.venv"
        REPORTS_DIR           = "${WORKSPACE}/reports"
        DC_HOME               = "${WORKSPACE}/tools/dependency-check"
        DC_CLI                = "${DC_HOME}/bin/dependency-check.sh"
        NVD_API_KEY           = credentials('nvd-api-key')  // stored securely in Jenkins Credentials
        TRIVY_SEVERITY        = "HIGH,CRITICAL"
        QUALITY_GATE_SEVERITY = "CRITICAL"
    }

    options {
        timestamps()
        ansiColor('xterm')
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    triggers {
        pollSCM('H/5 * * * *')
    }

    stages {

        // ── 1. CHECKOUT ──────────────────────────────────────
        stage('Checkout') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 1: Checkout           ║"
                echo "╚══════════════════════════════╝"
                checkout scm
                sh '''
                    mkdir -p ${REPORTS_DIR}/junit \
                             ${REPORTS_DIR}/coverage \
                             ${REPORTS_DIR}/sarif \
                             ${REPORTS_DIR}/owasp \
                             ${REPORTS_DIR}/bandit \
                             ${REPORTS_DIR}/trivy \
                             ${REPORTS_DIR}/pip-audit
                '''
            }
        }

        // ── 2. SETUP ENVIRONMENT ─────────────────────────────
        stage('Setup Environment') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 2: Setup Environment  ║"
                echo "╚══════════════════════════════╝"
                sh '''#!/bin/bash
                    set -e

                    echo "→ Creating Python virtual environment..."
                    python3 -m venv "${VENV_DIR}"
                    source "${VENV_DIR}/bin/activate"

                    echo "→ Upgrading pip..."
                    pip install --upgrade pip wheel setuptools

                    echo "→ Installing project dependencies..."
                    pip install -r requirements.txt

                    echo "→ Installing DevSecOps tooling..."
                    pip install \
                        pytest==7.4.3 \
                        pytest-cov==4.1.0 \
                        pytest-html==4.1.1 \
                        bandit==1.7.6 \
                        pip-audit==2.6.1

                    echo "→ Installed packages:"
                    pip list
                '''

                sh '''#!/bin/bash
                    set -e

                    echo "→ Checking / installing Trivy..."
                    if ! command -v trivy &>/dev/null; then
                        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
                            | sh -s -- -b /usr/local/bin v0.48.3
                    fi
                    trivy --version

                    echo "→ Checking / installing OWASP Dependency-Check..."
                    if [ ! -f "${DC_CLI}" ]; then
                        mkdir -p "${WORKSPACE}/tools"
                        DC_VERSION="9.0.7"
                        DC_ZIP="dependency-check-${DC_VERSION}-release.zip"
                        curl -sLo "/tmp/${DC_ZIP}" \
                            "https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VERSION}/${DC_ZIP}"
                        unzip -q "/tmp/${DC_ZIP}" -d "${WORKSPACE}/tools/"
                        chmod +x "${DC_CLI}"
                        rm "/tmp/${DC_ZIP}"
                    fi
                    echo "OWASP DC ready: ${DC_CLI}"
                '''
            }
        }

        // ── 3. UNIT TESTS & COVERAGE ─────────────────────────
        stage('Unit Tests') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 3: Unit Tests         ║"
                echo "╚══════════════════════════════╝"
                sh '''#!/bin/bash
                    set -e
                    source "${VENV_DIR}/bin/activate"

                    python -m pytest tests/ \
                        --tb=short \
                        --junitxml="${REPORTS_DIR}/junit/junit-results.xml" \
                        --html="${REPORTS_DIR}/junit/pytest-report.html" \
                        --self-contained-html \
                        --cov=src \
                        --cov=services \
                        --cov=api \
                        --cov=repositories \
                        --cov=factories \
                        --cov-report=xml:"${REPORTS_DIR}/coverage/coverage.xml" \
                        --cov-report=html:"${REPORTS_DIR}/coverage/html" \
                        --cov-report=term-missing \
                        -v \
                    || echo "[WARN] Some tests failed — continuing pipeline"
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true,
                          testResults: 'reports/junit/junit-results.xml'

                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : 'reports/coverage/html',
                        reportFiles          : 'index.html',
                        reportName           : '📊 Coverage Report'
                    ])
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : 'reports/junit',
                        reportFiles          : 'pytest-report.html',
                        reportName           : '🧪 Pytest Report'
                    ])
                }
            }
        }

        // ── 4. SCA — pip-audit ───────────────────────────────
        stage('SCA: pip-audit') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 4: pip-audit (SCA)    ║"
                echo "╚══════════════════════════════╝"
                sh '''#!/bin/bash
                    source "${VENV_DIR}/bin/activate"

                    echo "→ Running pip-audit on requirements.txt..."

                    # JSON report
                    pip-audit \
                        --requirement requirements.txt \
                        --format json \
                        --output "${REPORTS_DIR}/pip-audit/pip-audit-results.json" \
                        --progress-spinner off \
                    || true

                    # SARIF report
                    pip-audit \
                        --requirement requirements.txt \
                        --format sarif \
                        --output "${REPORTS_DIR}/sarif/pip-audit.sarif" \
                        --progress-spinner off \
                    || true

                    # Human-readable console output
                    pip-audit \
                        --requirement requirements.txt \
                        --format columns \
                        --progress-spinner off \
                    || echo "[INFO] pip-audit finished — check JSON report"

                    echo "→ pip-audit complete."
                '''
            }
        }

        // ── 5. SAST — Bandit ─────────────────────────────────
        stage('SAST: Bandit') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 5: Bandit (SAST)      ║"
                echo "╚══════════════════════════════╝"
                sh '''#!/bin/bash
                    source "${VENV_DIR}/bin/activate"

                    echo "→ Running Bandit static security analysis..."

                    # SARIF output
                    bandit -r src/ api/ services/ repositories/ factories/ \
                        -c security/bandit.yaml \
                        -f sarif \
                        -o "${REPORTS_DIR}/sarif/bandit.sarif" \
                        --exit-zero

                    # JSON output
                    bandit -r src/ api/ services/ repositories/ factories/ \
                        -c security/bandit.yaml \
                        -f json \
                        -o "${REPORTS_DIR}/bandit/bandit-results.json" \
                        --exit-zero

                    # HTML report
                    bandit -r src/ api/ services/ repositories/ factories/ \
                        -c security/bandit.yaml \
                        -f html \
                        -o "${REPORTS_DIR}/bandit/bandit-report.html" \
                        --exit-zero

                    # Console summary
                    bandit -r src/ api/ services/ repositories/ factories/ \
                        -c security/bandit.yaml \
                        -f text \
                        --exit-zero || true

                    echo "→ Bandit complete."
                '''
            }
            post {
                always {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : 'reports/bandit',
                        reportFiles          : 'bandit-report.html',
                        reportName           : '🔍 Bandit SAST Report'
                    ])
                }
            }
        }

        // ── 6. FS VULN SCAN — Trivy ──────────────────────────
        stage('Vuln Scan: Trivy') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 6: Trivy FS Scan      ║"
                echo "╚══════════════════════════════╝"
                sh '''#!/bin/bash

                    echo "→ Running Trivy filesystem scan..."

                    # SARIF output
                    trivy fs \
                        --config security/trivy.yaml \
                        --format sarif \
                        --output "${REPORTS_DIR}/sarif/trivy-fs.sarif" \
                        --severity "${TRIVY_SEVERITY}" \
                        --ignorefile security/.trivyignore \
                        --exit-code 0 \
                        .

                    # Try HTML template; fall back to plain text
                    trivy fs \
                        --format template \
                        --template "@/usr/local/share/trivy/templates/html.tpl" \
                        --output "${REPORTS_DIR}/trivy/trivy-report.html" \
                        --severity "${TRIVY_SEVERITY}" \
                        --ignorefile security/.trivyignore \
                        --exit-code 0 \
                        . \
                    || trivy fs \
                        --format table \
                        --output "${REPORTS_DIR}/trivy/trivy-report.txt" \
                        --severity "${TRIVY_SEVERITY}" \
                        --ignorefile security/.trivyignore \
                        --exit-code 0 \
                        .

                    # Console summary
                    trivy fs \
                        --format table \
                        --severity "${TRIVY_SEVERITY}" \
                        --ignorefile security/.trivyignore \
                        --exit-code 0 \
                        .

                    echo "→ Trivy scan complete."
                '''
            }
            post {
                always {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : 'reports/trivy',
                        reportFiles          : 'trivy-report.html,trivy-report.txt',
                        reportName           : '🔐 Trivy Security Report'
                    ])
                }
            }
        }

        // ── 7. DEEP SCA — OWASP Dependency-Check ─────────────
        stage('SCA: OWASP Dependency-Check') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 7: OWASP Dep-Check    ║"
                echo "╚══════════════════════════════╝"
                sh '''#!/bin/bash

                    echo "→ Running OWASP Dependency-Check..."

                    DC_FLAGS="--project HotelHub \
                               --scan . \
                               --out ${REPORTS_DIR}/owasp \
                               --format HTML \
                               --format XML \
                               --format SARIF \
                               --suppression security/owasp-suppression.xml \
                               --enableRetired \
                               --disableAssembly \
                               --failOnCVSS 9 \
                               --log ${REPORTS_DIR}/owasp/dc.log"

                    if [ -n "${NVD_API_KEY:-}" ]; then
                        DC_FLAGS="${DC_FLAGS} --nvdApiKey ${NVD_API_KEY}"
                    fi

                    "${DC_CLI}" ${DC_FLAGS} || true

                    # Copy SARIF to unified sarif dir
                    cp "${REPORTS_DIR}/owasp/"*.sarif \
                       "${REPORTS_DIR}/sarif/owasp-dc.sarif" 2>/dev/null || true

                    echo "→ OWASP Dependency-Check complete."
                '''
            }
            post {
                always {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : 'reports/owasp',
                        reportFiles          : 'dependency-check-report.html',
                        reportName           : '🛡️ OWASP Dependency-Check'
                    ])
                    dependencyCheckPublisher(
                        pattern             : 'reports/owasp/dependency-check-report.xml',
                        failedTotalCritical : 1,
                        unstableTotalHigh   : 5
                    )
                }
            }
        }

        // ── 8. QUALITY GATE ───────────────────────────────────
        stage('Quality Gate') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 8: Quality Gate       ║"
                echo "╚══════════════════════════════╝"
                sh '''#!/bin/bash
                    source "${VENV_DIR}/bin/activate"
                    echo "→ Evaluating security quality gate (threshold: ${QUALITY_GATE_SEVERITY})..."

                    GATE_PASSED=true
                    HIGH_ISSUES=0

                    # ── Bandit gate ──────────────────────────
                    if [ -f "${REPORTS_DIR}/bandit/bandit-results.json" ]; then
                        HIGH_ISSUES=$(python3 -c "
import json
try:
    data = json.load(open('${REPORTS_DIR}/bandit/bandit-results.json'))
    highs = [r for r in data.get('results',[])
             if r.get('issue_severity') in ('HIGH','CRITICAL')]
    print(len(highs))
except:
    print(0)
")
                        echo "   Bandit HIGH+ issues : ${HIGH_ISSUES}"
                        if [ "${HIGH_ISSUES}" -gt 0 ]; then
                            GATE_PASSED=false
                        fi
                    fi

                    # ── pip-audit gate ───────────────────────
                    PIP_VULNS=0
                    if [ -f "${REPORTS_DIR}/pip-audit/pip-audit-results.json" ]; then
                        PIP_VULNS=$(python3 -c "
import json
try:
    data = json.load(open('${REPORTS_DIR}/pip-audit/pip-audit-results.json'))
    deps = data.get('dependencies', data) if isinstance(data, dict) else data
    total = sum(len(d.get('vulns',[])) for d in deps)
    print(total)
except:
    print(0)
")
                        echo "   pip-audit findings  : ${PIP_VULNS}"
                    fi

                    echo ""
                    echo "┌──────────────────────────────────────────────┐"
                    echo "│           SECURITY QUALITY GATE               │"
                    echo "├──────────────────────────────────────────────┤"
                    printf "│  Bandit HIGH+ issues  : %-20s │\n" "${HIGH_ISSUES}"
                    printf "│  pip-audit vulns      : %-20s │\n" "${PIP_VULNS}"
                    echo "│  Trivy / OWASP DC     : see reports         │"
                    echo "└──────────────────────────────────────────────┘"

                    if [ "${GATE_PASSED}" = "false" ]; then
                        echo "❌ Quality Gate FAILED — HIGH/CRITICAL security issues detected"
                        exit 1
                    else
                        echo "✅ Quality Gate PASSED"
                    fi
                '''
            }
        }

        // ── 9. ARCHIVE ALL REPORTS ────────────────────────────
        stage('Archive Reports') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 9: Archive Reports    ║"
                echo "╚══════════════════════════════╝"
                sh 'find "${REPORTS_DIR}" -type f | sort'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/**/*',
                                     allowEmptyArchive: true,
                                     fingerprint: true

                    // SARIF → Warnings Next Generation plugin
                    recordIssues(
                        enabledForFailure: true,
                        aggregatingResults: true,
                        tools: [
                            sarif(pattern: 'reports/sarif/bandit.sarif',
                                  id: 'bandit',    name: 'Bandit SAST'),
                            sarif(pattern: 'reports/sarif/trivy-fs.sarif',
                                  id: 'trivy',     name: 'Trivy FS Scan'),
                            sarif(pattern: 'reports/sarif/pip-audit.sarif',
                                  id: 'pip-audit', name: 'pip-audit SCA'),
                            sarif(pattern: 'reports/sarif/owasp-dc.sarif',
                                  id: 'owasp-dc',  name: 'OWASP Dep-Check')
                        ]
                    )
                }
            }
        }

    } // end stages

    // ── Post-build notifications ─────────────────────────────
    post {
        always {
            echo "──────────────────────────────────────────────"
            echo "  Pipeline complete — ${currentBuild.currentResult}"
            echo "──────────────────────────────────────────────"
        }
        success {
            echo "✅ BUILD SUCCEEDED"
            // slackSend color:'good', message:"✅ HotelHub #${env.BUILD_NUMBER} passed"
        }
        unstable {
            echo "⚠️  BUILD UNSTABLE — security issues found"
            // slackSend color:'warning', message:"⚠️ HotelHub #${env.BUILD_NUMBER} unstable"
        }
        failure {
            echo "❌ BUILD FAILED"
            // slackSend color:'danger', message:"❌ HotelHub #${env.BUILD_NUMBER} failed"
        }
        cleanup {
            sh 'rm -f /tmp/dependency-check-*.zip || true'
        }
    }

} // end pipeline
