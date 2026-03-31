.PHONY: setup test test-docker lint typecheck verify clean deploy provision \
       test-unit test-infra generate-configs install download-plugins \
       verify-user-data

# Clone-and-run: make setup && make test
setup: generate-configs install download-plugins
	@test -f .env && chmod 600 .env && echo "Set .env permissions to 600" || true
	@echo "Setup complete. Configure .env, then: make deploy && make provision && make test"

install:
	python -m pip install -e '.[dev,demo]'

generate-configs:
	@test -f .env || (echo "Copy .env.template to .env and fill in values first" && exit 1)
	@bash -c 'source .env && sed "s/CHANGEME_RANGER_DB_PASSWORD/$${RANGER_DB_PASSWORD}/g" \
	    deploy/init-ranger-db.sql.template > deploy/init-ranger-db.generated.sql'
	@echo "Generated deploy/init-ranger-db.generated.sql"

download-plugins:
	bash deploy/setup-trino-connector.sh
	bash deploy/download-ranger-plugin.sh
	bash deploy/download-spark-connector.sh

deploy:
	docker compose --env-file .env -f deploy/docker-compose.yml up -d

provision:
	bash deploy/provision.sh

test:
	pytest tests/ -v --tb=short

test-unit:
	pytest tests/unit/ tests/arrow/ -v --tb=short

test-docker:
	docker compose --env-file .env -f deploy/docker-compose.yml --profile test run --rm test-runner

test-infra:
	pytest tests/positive/ tests/negative/ -v --tb=short -m "slow"

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

typecheck:
	mypy src/ --ignore-missing-imports

verify: lint typecheck test-unit
	@echo "All verification checks passed"

verify-user-data:
	@echo "Checking user-data.sh references match docker-compose.yml..."
	@python3 -c "\
	import re; \
	ud = open('deploy/user-data.sh').read(); \
	dc = open('deploy/docker-compose.yml').read(); \
	ud_imgs = set(re.findall(r'image:\s*(\S+)', ud)); \
	dc_imgs = set(re.findall(r'image:\s*(\S+)', dc)); \
	diff = ud_imgs.symmetric_difference(dc_imgs); \
	print('  Images in both: %s' % (ud_imgs & dc_imgs)); \
	print('  Differences: %s' % diff if diff else '  [OK] Image lists match'); \
	exit(1 if diff else 0)"

clean:
	docker compose -f deploy/docker-compose.yml down -v
	rm -rf data/snapshots/ data/entitlement_matrix.parquet
	rm -f deploy/init-ranger-db.generated.sql
