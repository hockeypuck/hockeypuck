all:

clean: stop
	docker-compose down -v

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
	echo "select * from userids order by identity asc;" | ./tests/dbq pg0
	echo "select * from userids order by identity asc;" | ./tests/dbq pg1
