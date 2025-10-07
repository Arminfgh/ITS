# ============================================================================
# SECUREOFFICE HUB - MAKEFILE
# Quick commands for development
# ============================================================================

.PHONY: help install test lint format docker-build docker-up docker-down clean

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "SecureOffice Hub - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $1, $2}'

# ============================================================================
# INSTALLATION
# ============================================================================

install: ## Install production dependencies
	pip install -r requirements.txt

install-dev: ## Install development dependencies
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install

# ============================================================================
# DEVELOPMENT
# ============================================================================

run: ## Run main application
	python main.py

dashboard: ## Start Streamlit dashboard
	streamlit run dashboard/app.py

api: ## Start FastAPI server
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

worker: ## Start Celery worker
	celery -A workers.celery_app worker --loglevel=info

beat: ## Start Celery beat scheduler
	celery -A workers.celery_app beat --loglevel=info

# ============================================================================
# TESTING
# ============================================================================

test: ## Run all tests
	pytest tests/ -v

test-cov: ## Run tests with coverage
	pytest tests/ -v --cov=. --cov-report=html --cov-report=term

test-fast: ## Run tests (fast mode)
	pytest tests/ -v -x --ff

# ============================================================================
# CODE QUALITY
# ============================================================================

lint: ## Run linters
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=120 --statistics
	pylint **/*.py --exit-zero

format: ## Format code with black and isort
	black .
	isort .

format-check: ## Check code formatting
	black --check .
	isort --check-only .

type-check: ## Run type checking with mypy
	mypy . --ignore-missing-imports

security: ## Run security checks
	bandit -r . -ll
	safety check

# ============================================================================
# DOCKER
# ============================================================================

docker-build: ## Build Docker images
	docker-compose build

docker-up: ## Start Docker containers
	docker-compose up -d

docker-down: ## Stop Docker containers
	docker-compose down

docker-logs: ## Show Docker logs
	docker-compose logs -f

docker-ps: ## Show running containers
	docker-compose ps

docker-clean: ## Remove Docker containers and volumes
	docker-compose down -v
	docker system prune -f

# ============================================================================
# DATABASE
# ============================================================================

db-init: ## Initialize database
	python -c "from database.models import init_database; from config import DATABASE_URL; init_database(DATABASE_URL)"

db-reset: ## Reset database (WARNING: deletes all data!)
	rm -f database/security.db
	$(MAKE) db-init

# ============================================================================
# CLEANING
# ============================================================================

clean: ## Clean generated files
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	find . -type d -name '*.egg-info' -exec rm -rf {} +
	find . -type f -name '.coverage' -delete
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf build/
	rm -rf dist/

clean-all: clean ## Clean everything including data
	rm -rf data/scan_results/*
	rm -rf data/reports/*
	rm -rf logs/*.log

# ============================================================================
# DOCUMENTATION
# ============================================================================

docs: ## Generate documentation
	mkdocs build

docs-serve: ## Serve documentation locally
	mkdocs serve

# ============================================================================
# DEPLOYMENT
# ============================================================================

deploy-prod: ## Deploy to production (placeholder)
	@echo "Deployment to production..."
	@echo "TODO: Add your deployment commands here"

# ============================================================================
# UTILITIES
# ============================================================================

check-all: format-check lint type-check security test ## Run all checks

demo: ## Run demo mode
	python -c "from main import run_demo_mode; run_demo_mode()"

version: ## Show version info
	@python --version
	@pip --version
	@echo "SecureOffice Hub v1.0.0"

env-check: ## Check environment setup
	@echo "Checking environment..."
	@python -c "import sys; print(f'Python: {sys.version}')"
	@python -c "import streamlit; print(f'Streamlit: {streamlit.__version__}')"
	@python -c "import fastapi; print(f'FastAPI: {fastapi.__version__}')"
	@echo "✅ Environment OK"