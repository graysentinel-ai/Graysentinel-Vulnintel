# Contributing to GRAYSENTINEL VULNINTEL

First off — thank you for considering contributing! This project exists
because of community contributions. We welcome code, docs, bug reports,
and feature ideas.

---

## 📜 Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md).
Violations may result in a ban from the project.

**TL;DR:** Be respectful. No harassment, discrimination, or abuse.
Zero tolerance for contributors who use this tool for unauthorized scanning.

---

## ⚠️ Legal Requirement

This is an **offensive security tool**. Contributors **MUST**:

- ❌ **Never** submit code that scans without authorization
- ❌ **Never** include real-world target lists or attack data
- ❌ **Never** commit credentials, API keys, or customer data
- ❌ **Never** add automatic exploitation capabilities
- ✅ **Always** include clear legal disclaimers on new features
- ✅ **Always** document authorization requirements

**PRs violating these rules will be closed without review.**

---

## 🚀 How to Contribute

### 1. Fork & Clone

```bash
# Fork via GitHub UI, then:
git clone https://github.com/YOUR_USERNAME/graysentinel-vulnintel.git
cd graysentinel-vulnintel

# Setup dev environment
python3.13 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
