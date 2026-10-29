.PHONY: setup lint format typecheck test check check-all clean reproduce integration

setup:
	uv sync

lint:
	uv run ruff check .

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

typecheck:
	uv run mypy src tests

test:
	uv run pytest

integration:
	uv run pytest -m integration

reproduce:
	uv run ruleproof fetch
	uv run ruleproof run
	@echo "--- Output Verification ---"
	@shasum -a 256 outputs/classification.csv outputs/results.jsonl

check: check-all

check-all: lint format-check typecheck test

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info
