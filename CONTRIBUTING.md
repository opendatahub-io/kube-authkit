# Contributing to Kube AuthKit

Thank you for your interest in contributing to Kube AuthKit! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Finding Issues to Work On

- Check the [Issues](https://github.com/kube-authkit/kube-authkit/issues) page
- Look for issues labeled `good first issue` or `help wanted`
- Comment on an issue to let others know you're working on it

## Development Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/kube-authkit.git
   cd kube-authkit
   ```

2. **Install uv** (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **Install dependencies**:
   ```bash
   uv pip install -e ".[dev]"
   ```

4. **Verify installation**:
   ```bash
   python -c "import kube_authkit; print(kube_authkit.__version__)"
   pytest --version
   ```

## Development Workflow

### Creating a Branch

Create a feature branch from `main`:

```bash
git checkout main
git pull origin main
git checkout -b feat/your-feature-name
```

Branch naming conventions:
- `feat/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `test/` - Test additions/improvements
- `refactor/` - Code refactoring

### Making Changes

1. **Write code** following our code style guidelines
2. **Add tests** for new functionality
3. **Update documentation** if needed
4. **Run tests** to ensure nothing breaks

## Running Tests

### Run all tests:
```bash
pytest tests/
```

### Run only unit tests:
```bash
pytest tests/ -m "not integration"
```

### Run only integration tests:
```bash
pytest tests/ -m integration
```

### Run with coverage:
```bash
pytest tests/ --cov=src/kube_authkit --cov-report=term
```

### Run specific test file:
```bash
pytest tests/strategies/test_oidc.py -v
```

## Code Style

### Tools

This project uses:
- **Black** for code formatting
- **Ruff** for linting
- **mypy** for type checking
- **Bandit** for security scanning

### Running Code Quality Checks

```bash
# Format code
black src/ tests/

# Lint code
ruff check src/ tests/

# Type check
mypy src/kube_authkit

# Security scan
bandit -r src/kube_authkit
```

### Style Guidelines

- **Line length**: 100 characters
- **Type hints**: Required for all function signatures
- **Docstrings**: Required for public modules, classes, and functions (Google-style)
- **Imports**: Organized with isort (via Ruff)

## Submitting Changes

### Commit Messages

Write clear, descriptive commit messages:

```
feat: add support for Azure Entra ID authentication

- Implement AzureEntraStrategy class
- Add Azure-specific configuration options
- Include unit and integration tests

Closes #123
```

Format:
- **Type**: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`
- **Subject**: Brief description (50 chars or less)

### Creating a Pull Request

1. Push your branch: `git push origin feat/your-feature-name`
2. Create Pull Request on GitHub
3. Address any review feedback
4. Once approved, your PR will be merged

## Release Process

See [PUBLISHING.md](PUBLISHING.md) for detailed release instructions.

## Questions?

- **Bug reports**: Open an [Issue](https://github.com/kube-authkit/kube-authkit/issues)
- **General questions**: Start a discussion

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
