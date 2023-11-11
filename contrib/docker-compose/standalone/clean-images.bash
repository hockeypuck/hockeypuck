#!/bin/bash

# Remove temporary images that `docker build` leaves behind.
docker images -f 'label=io.hockeypuck.temp=true' -q | xargs docker rmi
