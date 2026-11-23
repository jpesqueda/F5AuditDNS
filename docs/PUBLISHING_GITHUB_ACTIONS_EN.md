# Publish F5AuditDNS using GitHub Actions (English)

[Español](PUBLISHING_GITHUB_ACTIONS_ES.md) · [English user guide](USER_GUIDE_EN.md)

This project has three workflows: `.github/workflows/ci.yml` tests pushes and pull requests; `.github/workflows/publish-testpypi.yml` supports manually triggered TestPyPI publishing; `.github/workflows/release.yml` publishes **non-prerelease** GitHub Releases to PyPI using **Trusted Publishing (OIDC)**. The current example development version is `0.5.2`; do **not** create a release until review and TMOS validation are complete.

## 1. Prepare the repository

Copy the contents of the source package into a development branch and open a pull request. Never commit real BIG-IP RAW snapshots, IP inventories, credentials or UCS archives. Execute `python -m pytest -q`, `python -m build` and `python -m twine check dist/*`. Check that English and Spanish sections are both present in the built wheel's `METADATA` under `Description`/`README.md`.

## 2. Configure GitHub environments

Repository → Settings → Environments: create `testpypi` and `pypi`. Protect `pypi` with required reviewers or tag restrictions where your repository plan permits it.

## 3. Configure Trusted Publishers

On https://test.pypi.org/manage/account/publishing/ register or update a Trusted Publisher for project `f5auditdns`, with your real GitHub owner, repository `F5AuditDNS`, workflow `publish-testpypi.yml`, and environment `testpypi`. On https://pypi.org/manage/account/publishing/ configure workflow `release.yml` and environment `pypi`. TestPyPI and PyPI maintain independent account settings.

## 4. TestPyPI validation

GitHub → Actions → **Publish F5AuditDNS to TestPyPI** → **Run workflow**. The workflow tests, builds, validates and uploads to TestPyPI. A package name/version combination is immutable after upload, so bump the version for another attempt. In an isolated environment, install a downloaded wheel or inspect its metadata.

## 5. Production release

Once CI and real-TMOS review have passed, set matching versions in `pyproject.toml` and `f5auditdns/__init__.py`, merge to `main`, and create a **non-prerelease** GitHub Release with tag `v0.5.2` for this example. The release workflow checks the tag matches `pyproject.toml`, runs tests, builds and publishes via OIDC. Use a later unused version if 0.5.2 has already been published. Do not publish a GitHub Release before it is approved: it triggers PyPI automatically.

## 6. Verify the bilingual PyPI page

`[project] readme = "README.md"` makes PyPI render the **single README containing English and Spanish**; there is no automatic language-tab switch. Verify English and Español headings, Markdown, code examples and absolute GitHub documentation links on the project page. Metadata classifiers advertise both languages; those classifiers do not translate the text themselves.

## 7. Install after publication

```powershell
py -m pip install --upgrade f5auditdns==0.5.2
f5auditdns --version
```

Use the PyPI index only for versions actually published, and keep sensitive infrastructure details out of public releases.

References: https://docs.pypi.org/trusted-publishers/using-a-publisher/ and https://packaging.python.org/en/latest/guides/making-a-pypi-friendly-readme/
