# Publishing to PyPI

This document explains how to publish `kube-authkit` to PyPI using the automated CI/CD pipeline.

## Prerequisites

### 1. PyPI Trusted Publishing Setup

This project uses **PyPI Trusted Publishing** (no API tokens needed!) for secure, automated releases.

#### Configure PyPI Trusted Publishing:

1. **Go to PyPI**: https://pypi.org/manage/account/publishing/
2. **Add a new publisher**:
   - **PyPI Project Name**: `kube-authkit`
   - **Owner**: `kube-authkit` (or your GitHub org/username)
   - **Repository name**: `kube-authkit`
   - **Workflow name**: `publish.yml`
   - **Environment name**: `pypi`

3. **For TestPyPI** (optional, for testing): https://test.pypi.org/manage/account/publishing/
   - Follow same steps with environment name: `testpypi`

#### Configure GitHub Environments:

1. Go to your repository **Settings → Environments**
2. Create environment: `pypi`
   - Add protection rules (optional):
     - Required reviewers
     - Deployment branches: Only `main` or tags matching `v*`
3. Create environment: `testpypi` (optional)

## Publishing Workflow

### Automated Release (Recommended)

The CI/CD pipeline automatically publishes to PyPI when you create a GitHub release:

1. **Update version** in `pyproject.toml`:
   ```toml
   version = "0.2.0"
   ```

2. **Commit and push**:
   ```bash
   git add pyproject.toml
   git commit -m "Bump version to 0.2.0"
   git push origin main
   ```

3. **Create and push a version tag**:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. **Create GitHub Release**:
   - The `release.yml` workflow will automatically create a GitHub release
   - OR manually create one at: https://github.com/kube-authkit/kube-authkit/releases/new
   - Use tag: `v0.2.0`
   - Generate release notes automatically

5. **Automated Publishing**:
   - The `publish.yml` workflow triggers on release creation
   - Runs all tests
   - Builds the package
   - Publishes to PyPI automatically
   - View progress in Actions tab

### Manual Testing with TestPyPI

To test the release process without publishing to production PyPI:

1. **Trigger manual workflow**:
   - Go to Actions → "Publish to PyPI" workflow
   - Click "Run workflow"
   - Check "Publish to Test PyPI"
   - Click "Run workflow"

2. **Test installation from TestPyPI**:
   ```bash
   pip install --index-url https://test.pypi.org/simple/ kube-authkit
   ```

## Manual Publishing (Emergency Only)

If you need to publish manually (e.g., CI is broken):

1. **Install build tools**:
   ```bash
   pip install build twine
   ```

2. **Build the package**:
   ```bash
   python -m build
   ```

3. **Check the package**:
   ```bash
   twine check dist/*
   ```

4. **Upload to TestPyPI (optional)**:
   ```bash
   twine upload --repository testpypi dist/*
   ```

5. **Upload to PyPI**:
   ```bash
   twine upload dist/*
   ```

   You'll need a PyPI API token for manual uploads:
   - Create at: https://pypi.org/manage/account/token/
   - Username: `__token__`
   - Password: `pypi-...your-token...`

## Versioning Scheme

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version (1.0.0): Incompatible API changes
- **MINOR** version (0.1.0): Add functionality (backwards-compatible)
- **PATCH** version (0.0.1): Bug fixes (backwards-compatible)

Pre-release versions:
- `0.1.0-alpha.1` - Alpha release
- `0.1.0-beta.1` - Beta release
- `0.1.0-rc.1` - Release candidate

## Release Checklist

Before creating a release:

- [ ] All tests passing on main branch
- [ ] Version bumped in `pyproject.toml`
- [ ] CHANGELOG.md updated (if maintained)
- [ ] README.md updated with new features (if applicable)
- [ ] Documentation updated
- [ ] Migration guide written (for breaking changes)
- [ ] Tag created with `v` prefix (e.g., `v0.2.0`)

## Troubleshooting

### Trusted Publishing Issues

**Error: "Trusted publishing exchange failure"**
- Verify publisher configuration on PyPI matches exactly
- Check workflow name is `publish.yml`
- Ensure environment name is `pypi`
- Repository owner/name must match

**Error: "Environment not found"**
- Create the environment in GitHub Settings → Environments
- Ensure spelling matches exactly (`pypi` not `PyPI`)

### Build Issues

**Error: "Package build failed"**
- Run `python -m build` locally to debug
- Check `pyproject.toml` syntax
- Ensure all required files are included

**Error: "Tests failed"**
- Fix failing tests before releasing
- Run `pytest` locally to verify

### Version Conflicts

**Error: "File already exists"**
- Cannot re-upload same version to PyPI
- Bump version number
- Delete local `dist/` directory before building

## Resources

- [PyPI Trusted Publishing Guide](https://docs.pypi.org/trusted-publishers/)
- [Python Packaging Guide](https://packaging.python.org/)
- [Semantic Versioning](https://semver.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
