# Contributing to pyruijie

## Development Setup

```bash
# Clone and install in development mode
git clone https://github.com/dannielperez/pyruijie.git
cd pyruijie
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest                                    # run all tests
pytest --cov=pyruijie --cov-report=term   # with coverage
pytest tests/test_client.py -v            # single file
```

## Linting

```bash
ruff check src/ tests/       # lint
ruff format --check src/ tests/  # format check
ruff format src/ tests/      # auto-format
```

## Building

```bash
python -m build              # build sdist + wheel
twine check dist/*           # verify metadata
```

## Verifying a Release Locally

```bash
# Build and inspect
python -m build
twine check dist/*

# Verify py.typed is included
python -c "
import zipfile, pathlib
whl = next(pathlib.Path('dist').glob('*.whl'))
with zipfile.ZipFile(whl) as z:
    assert any('py.typed' in n for n in z.namelist())
    print(f'py.typed present in {whl.name}')
"

# Smoke test from wheel
pip install dist/*.whl
python -c "import pyruijie; print(pyruijie.__version__)"
```

## Publishing

Releases are automated via GitHub Actions when a version tag is pushed:

```bash
# 1. Update version in pyproject.toml and src/pyruijie/__init__.py
# 2. Move [Unreleased] entries to a versioned section in CHANGELOG.md
# 3. Commit: git commit -am "release: v0.3.0"
# 4. Tag:    git tag v0.3.0
# 5. Push:   git push origin main --tags
```

The CI pipeline will:
1. Build sdist and wheel
2. Run `twine check`
3. Publish to TestPyPI
4. Publish to PyPI (requires manual approval)

## Guidelines

- Keep changes focused and reviewable
- Add tests for new functionality
- Preserve backward compatibility with existing consumers
- Use Pydantic `Field(alias=...)` for API field mappings
- Run `ruff check` and `ruff format` before committing
- Update CHANGELOG.md under `[Unreleased]`
