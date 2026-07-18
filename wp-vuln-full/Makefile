# wp2shell lab — one-command vulnerable/patched validation.
WP_PORT        ?= 8889
WP_VULN_TAG    ?= 6.9.4
WP_PATCHED_TAG ?= 7.0.2
BASE            = http://localhost:$(WP_PORT)
POC             = ../../Downloads/wp2shell.py
export WP_PORT

.PHONY: help up check exploit proof patched down clean

help:
	@echo "make up          start vulnerable WordPress $(WP_VULN_TAG) + install"
	@echo "make check       non-destructive vulnerability probe"
	@echo "make exploit     full pre-auth RCE chain against the lab"
	@echo "make proof       SQLi evidence (@@version, current_user)"
	@echo "make patched     switch to WordPress $(WP_PATCHED_TAG) and re-check"
	@echo "make down        stop and remove the lab (with volumes)"
	@echo ""
	@echo "Options (override defaults):"
	@echo "  WP_PORT=8093 make up"
	@echo "  WP_TAG=6.8.3 make up     # SQLi-only branch"
	@echo "  WP_TAG=7.0.2 make up     # patched version"

up:
	WP_TAG=$(WP_VULN_TAG) WP_PORT=$(WP_PORT) docker compose up -d
	@echo "lab up (vulnerable $(WP_VULN_TAG)): $(BASE)"
	@echo "admin / Admin!2345"

install:
	@# wait for wpcli to finish (LAB READY in logs)
	@while ! docker compose logs wpcli 2>/dev/null | grep -q "LAB READY"; do sleep 2; done
	@echo "WordPress ready at $(BASE)"

check:
	python3 $(POC) $(BASE) --check

exploit:
	python3 $(POC) $(BASE) --exploit

proof:
	python3 $(POC) $(BASE) --extract "SELECT @@version" --skip-version-check
	@echo ""
	python3 $(POC) $(BASE) --extract "SELECT CURRENT_USER()" --skip-version-check

patched:
	docker compose down -v --remove-orphans
	WP_TAG=$(WP_PATCHED_TAG) WP_PORT=$(WP_PORT) docker compose up -d
	@while ! docker compose logs wpcli 2>/dev/null | grep -q "LAB READY"; do sleep 2; done
	python3 $(POC) $(BASE) --check

down clean:
	docker compose down -v --remove-orphans
