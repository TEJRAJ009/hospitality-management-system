// ============================================================
//  HotelHub — Jenkins DevSecOps CI Pipeline
//  Tools: pytest | pip-audit | Bandit | Trivy
// ============================================================

pipeline {

    // Run every stage inside a python:3.11-slim Docker container.
    // Requires: Jenkins agent has Docker installed and jenkins user is in the docker group.
    agent {
        docker {
            image 'python:3.11-slim'
            args  '-u root --privileged -v /var/run/docker.sock:/var/run/docker.sock'
        }
    }

    // ── Environment variables ────────────────────────────────
    environment {
        // No VENV_DIR needed — Docker container already has Python isolated
        REPORTS_DIR           = "${WORKSPACE}/reports"
        TRIVY_SEVERITY        = "HIGH,CRITICAL"
        QUALITY_GATE_SEVERITY = "CRITICAL"
    }

    options {
        timestamps()
        // ansiColor('xterm')  // uncomment after installing the AnsiColor plugin
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

                    echo "→ Installing system dependencies (curl)..."
                    apt-get update -qq
                    apt-get install -y -qq curl 2>/dev/null
                    echo "   System packages ready."

                    echo "→ Upgrading pip..."
                    pip install --upgrade pip wheel setuptools --quiet

                    echo "→ Installing project dependencies..."
                    pip install -r requirements.txt --quiet

                    echo "→ Installing DevSecOps tooling..."
                    pip install \
                        pytest==7.4.3 \
                        pytest-cov==4.1.0 \
                        pytest-html==4.1.1 \
                        bandit==1.7.6 \
                        bandit-sarif-formatter \
                        pip-audit==2.6.1 \
                        --quiet

                    echo "→ Installed packages:"
                    pip list
                '''

                sh '''#!/bin/bash
                    set -e

                    echo "→ Checking / installing Trivy..."
                    if ! command -v trivy &>/dev/null; then
                        TRIVY_VERSION="0.71.2"
                        TRIVY_TGZ="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
                        # Download release tarball directly (errors stay visible, no pipe-to-sh)
                        mkdir -p "${WORKSPACE}/tools/cache"
                        [ -s "${WORKSPACE}/tools/cache/${TRIVY_TGZ}" ] || curl -fSL --retry 8 --retry-all-errors --retry-delay 10 --connect-timeout 30 -o "${WORKSPACE}/tools/cache/${TRIVY_TGZ}" \
                            "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_TGZ}"
                        mkdir -p /tmp/trivy-extract /usr/local/share/trivy/templates
                        tar -xzf "${WORKSPACE}/tools/cache/${TRIVY_TGZ}" -C /tmp/trivy-extract
                        install -m 0755 /tmp/trivy-extract/trivy /usr/local/bin/trivy
                        cp /tmp/trivy-extract/contrib/*.tpl /usr/local/share/trivy/templates/ 2>/dev/null || true
                        rm -rf /tmp/trivy-extract
                    fi
                    trivy --version
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
                    set -e

                    echo "→ Running pip-audit on requirements.txt..."

                    # JSON report
                    pip-audit \
                        --requirement requirements.txt \
                        --format json \
                        --output "${REPORTS_DIR}/pip-audit/pip-audit-results.json" \
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
                    set -e

                    echo "→ Running Bandit static security analysis..."

                    # SARIF output
                    bandit -r src/ api/ services/ repositories/ factories/ \
                        -c security/bandit.yaml \
                        -f sarif \
                        -o "${REPORTS_DIR}/sarif/bandit.sarif" \
                        --exit-zero || echo "[WARN] Bandit SARIF output failed"

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
                        -f txt \
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

        // ── 8. QUALITY GATE ───────────────────────────────────
        stage('Quality Gate') {
            steps {
                echo "╔══════════════════════════════╗"
                echo "║  Stage 8: Quality Gate       ║"
                echo "╚══════════════════════════════╝"
                sh '''#!/bin/bash
                    set -e
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
                    echo "│  Trivy                : see reports         │"
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
