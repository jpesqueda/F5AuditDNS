# v0.5.3 test report

- Local environment: Python 3.13 on Linux.
- Result: **136 passed**, including 106 existing regression tests and 30 diagram tests.
- Mock and existing RAW+LTM snapshots: both diagram modes generated portable HTML and JSON successfully.
- Source artifacts: wheel and sdist built locally through setuptools.
- Browser note: JavaScript syntax validated by Node.js; a graphical browser smoke test was unavailable in this container.
- Windows 3.9/3.12 and Ubuntu CI matrix: **pending GitHub Actions**, NOT yet asserted to have passed for this version.
- TMOS 17.5.1.11 live validation: **pending**. No BIG-IP changes were performed.

All test identities are synthetic and documentation IP ranges are used.
