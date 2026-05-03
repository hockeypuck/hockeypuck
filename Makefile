PROJECTPATH = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
export GOPATH := $(PROJECTPATH)
export GOCACHE := $(GOPATH)/.gocache
export SRCDIR := $(PROJECTPATH)src/hockeypuck
VERSION ?= $(shell git describe --tags 2>/dev/null)
TIMESTAMP = $(shell date -Iseconds -u)
GOTAGS = v5

project = hockeypuck

prefix = /usr
statedir = /var/lib/$(project)

commands = \
	$(project) \
	$(project)-dump \
	$(project)-load \
	$(project)-pbuild \
	$(project)-reload

all: test build

build:

clean: clean-go
	rm -rf debian/{.debhelper/,$(project).debhelper.log,$(project).postinst.debhelper,$(project).postrm.debhelper,$(project).prerm.debhelper,$(project).substvars,$(project)/}

clean-go:
	-chmod -R u+rwX pkg
	rm -rf $(PROJECTPATH)/.gocache
	rm -rf $(PROJECTPATH)/bin
	rm -rf $(PROJECTPATH)/pkg

dch:
	gbp dch --debian-tag='%(version)s' -D bionic --git-log --first-parent

deb-src:
	debuild -S -sa -I

install:
	mkdir -p -m 0755 $(DESTDIR)$(prefix)/bin
	cp -a bin/$(project)* $(DESTDIR)$(prefix)/bin
	mkdir -p -m 0755 $(DESTDIR)/etc/$(project)
	cp -a contrib/config/$(project).conf* $(DESTDIR)/etc/$(project)
	mkdir -p -m 0755 $(DESTDIR)$(statedir)/templates
	cp -a contrib/templates/*.tmpl $(DESTDIR)$(statedir)/templates
	mkdir -p -m 0755 $(DESTDIR)$(statedir)/www
	cp -a contrib/webroot/* $(DESTDIR)$(statedir)/www

install-build-depends:
	sudo apt install -y \
	    debhelper \
		dh-systemd \
	    git-buildpackage \
	    golang

lint: lint-go

lint-go:
	cd $(SRCDIR) && ! go fmt $(project)/... | awk '/./ {print "ERROR: go fmt made unexpected changes:", $$0}' | grep .
	cd $(SRCDIR) && go vet $(project)/...

test: test-go

test-coverage:
	cd $(SRCDIR) && go test -tags=${GOTAGS} -coverprofile=${PROJECTPATH}/cover.out $(project)/...
	cd $(SRCDIR) && go tool cover -tags=${GOTAGS} -html=${PROJECTPATH}/cover.out
	rm cover.out

test-go:
	cd $(SRCDIR) && go test -tags=${GOTAGS} $(project)/... -count=1

test-postgresql:
	cd $(SRCDIR) && POSTGRES_TESTS=1 go test -tags=${GOTAGS} $(project)/pgtest/... -count=1 -timeout 60s
	cd $(SRCDIR) && POSTGRES_TESTS=1 go test -tags=${GOTAGS} $(project)/pghkp/... -count=1 -timeout 180s

#
# Generate targets to build Go commands.
#
define make-go-cmd-target
	$(eval cmd_name := $1)
	$(eval cmd_package := $(project)/server/cmd/$(cmd_name))
	$(eval cmd_target := $(cmd_name))

$(cmd_target):
	cd $(SRCDIR) && \
	go install -tags=${GOTAGS} -ldflags " \
			-X $(project)/server.Version=$(VERSION) \
			-X $(project)/server.BuiltAt=$(TIMESTAMP) \
		" $(cmd_package)

build: $(cmd_target)

endef

$(foreach command,$(commands),$(eval $(call make-go-cmd-target,$(command))))
