#!/usr/bin/env bash
# ============================================================
#  install-tools.sh — DevSecOps tool installer for Jenkins agent
#  Run once on a fresh agent or inside a Dockerfile.
#  Usage: bash scripts/install-tools.sh
# ============================================================
set -euo pipefail

TRIVY_VERSION="0.48.3"
OWASP_DC_VERSION="9.0.7"
INSTALL_DIR="/usr/local/bin"
DC_INSTALL_DIR="${HOME}/tools/dependency-check"

echo "========================================"
echo "  HotelHub — DevSecOps Tool Installer  "
echo "========================================"

# ── 1. Trivy ─────────────────────────────────────────────────
echo ""
echo "→ Installing Trivy ${TRIVY_VERSION}..."
if command -v trivy &>/dev/null; then
    echo "   Trivy already installed: $(trivy --version | head -1)"
else
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b "${INSTALL_DIR}" "v${TRIVY_VERSION}"
    echo "   ✓ Trivy installed: $(trivy --version | head -1)"
fi

# ── 2. OWASP Dependency-Check ─────────────────────────────────
echo ""
echo "→ Installing OWASP Dependency-Check ${OWASP_DC_VERSION}..."
DC_CLI="${DC_INSTALL_DIR}/bin/dependency-check.sh"
if [ -f "${DC_CLI}" ]; then
    echo "   OWASP DC already installed at ${DC_CLI}"
else
    mkdir -p "${HOME}/tools"
    DC_ZIP="dependency-check-${OWASP_DC_VERSION}-release.zip"
    TMP_ZIP="/tmp/${DC_ZIP}"
    echo "   Downloading ${DC_ZIP}..."
    curl -sLo "${TMP_ZIP}" \
        "https://github.com/jeremylong/DependencyCheck/releases/download/v${OWASP_DC_VERSION}/${DC_ZIP}"
    echo "   Extracting..."
    unzip -q "${TMP_ZIP}" -d "${HOME}/tools/"
    chmod +x "${DC_CLI}"
    rm "${TMP_ZIP}"
    echo "   ✓ OWASP DC installed at ${DC_CLI}"
fi

# ── 3. Python DevSecOps packages ─────────────────────────────
echo ""
echo "→ Installing Python DevSecOps packages..."
pip install --upgrade \
    bandit==1.7.6 \
    pip-audit==2.6.1 \
    pytest==7.4.3 \
    pytest-cov==4.1.0 \
    pytest-html==4.1.1
echo "   ✓ Python packages installed"

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  Installation Complete"
echo "========================================"
echo "  Trivy         : $(trivy --version 2>/dev/null | head -1 || echo 'not found')"
echo "  OWASP DC CLI  : ${DC_CLI}"
echo "  bandit        : $(bandit --version 2>/dev/null || echo 'not found')"
echo "  pip-audit     : $(pip-audit --version 2>/dev/null || echo 'not found')"
echo "========================================"
