# Releasing AIperture

Releases are published to [PyPI](https://pypi.org/project/aiperture/) automatically via GitHub Actions when a new GitHub release is created.

## Steps

1. **Bump the version** in two files:
   - `pyproject.toml` → `version = "X.Y.Z"`
   - `aiperture/api/app.py` → `version="X.Y.Z"`

2. **Commit and push:**
   ```bash
   git add pyproject.toml aiperture/api/app.py
   git commit -m "Bump version to X.Y.Z"
   git push
   ```

3. **Tag and push the tag:**
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

4. **Create the GitHub release:**
   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" --notes "Release notes here"
   ```

5. **Verify** the publish workflow succeeded:
   ```bash
   gh run list --limit 1
   ```

The package will be live at https://pypi.org/project/aiperture/ within a minute.

## How it works

- `.github/workflows/publish.yml` triggers on `release: [published]`
- Uses [trusted publishing](https://docs.pypi.org/trusted-publishers/) (no API tokens needed)
- The `pypi` GitHub environment is configured as the trusted publisher on PyPI
- Builds with `python -m build`, publishes with `pypa/gh-action-pypi-publish`

## Versioning

We use [semver](https://semver.org/):
- **Patch** (0.3.1 → 0.3.2): Bug fixes, doc updates, minor improvements
- **Minor** (0.3.x → 0.4.0): New features, new CLI commands, new config settings
- **Major** (0.x → 1.0): Breaking API changes, stable release
