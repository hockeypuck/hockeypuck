all:

clean: stop
	docker-compose down -v

init:
	#init is currently a no-op; it will someday build the individual node configs
	@echo

scenario%:
	docker-compose --env-file .env.$@ up -d
	@echo
	@echo "WARNING: please wait five minutes for the cluster to stabilise"
	@echo

stop:
	docker-compose down

test:
	./tests/totals
	./tests/pkslog
