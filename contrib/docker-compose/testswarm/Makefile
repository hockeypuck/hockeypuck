all:

clean:
	$(foreach e,$(wildcard .env.*),docker-compose --env-file $e down -v;)

init:
	#init is currently a no-op; it will someday build the individual node configs
	@echo

scenario%:
	docker-compose --env-file .env.$@ up -d
	@echo
	@echo "WARNING: please wait 60 seconds for the cluster to stabilise"
	@echo

stop:
	docker-compose down

test:
	./tests/totals
	./tests/pkslog
	./tests/userids

testhkp:
	./tests/hkp
