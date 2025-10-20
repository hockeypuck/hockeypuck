PROJECTPATH = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
export GOPATH := $(PROJECTPATH)
export GOCACHE := $(GOPATH)/.gocache
export SRCDIR := $(PROJECTPATH)src/hockeypuck
VERSION ?= $(shell git describe --tags 2>/dev/null)
TIMESTAMP = $(shell date -Iseconds -u)

project = hockeypuck

prefix = /usr
statedir = /var/lib/$(project)

commands = \
	hockeypuck \
	hockeypuck-dump \
	hockeypuck-load \
	hockeypuck-pbuild \
	hockeypuck-reload \
	ratelimit-tester

all: test build

build:

clean: clean-go
	rm -rf debian/{.debhelper/,hockeypuck.debhelper.log,hockeypuck.postinst.debhelper,hockeypuck.postrm.debhelper,hockeypuck.prerm.debhelper,hockeypuck.substvars,hockeypuck/}

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
	cp -a bin/hockeypuck* $(DESTDIR)$(prefix)/bin
	mkdir -p -m 0755 $(DESTDIR)/etc/hockeypuck
	cp -a contrib/config/hockeypuck.conf* $(DESTDIR)/etc/hockeypuck
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
	cd $(SRCDIR) && go test -coverprofile=${PROJECTPATH}/cover.out $(project)/...
	cd $(SRCDIR) && go tool cover -html=${PROJECTPATH}/cover.out
	rm cover.out

test-go:
	cd $(SRCDIR) && go test $(project)/... -count=1

test-postgresql:
	cd $(SRCDIR) && POSTGRES_TESTS=1 go test $(project)/pghkp/... -count=1
	cd $(SRCDIR) && POSTGRES_TESTS=1 go test $(project)/pgtest/... -count=1

#
# Generate targets to build Go commands.
# Note: ratelimit-tester is in hockeypuck/ratelimit/cmd/, others are in hockeypuck/server/cmd/
#
define make-go-cmd-target
	$(eval cmd_name := $1)
	$(eval cmd_package := $(if $(filter ratelimit-tester,$1),$(project)/ratelimit/cmd/$(cmd_name),$(project)/server/cmd/$(cmd_name)))
	$(eval cmd_target := $(cmd_name))

$(cmd_target):
	cd $(SRCDIR) && \
	go install -ldflags " \
			-X hockeypuck/server.Version=$(VERSION) \
			-X hockeypuck/server.BuiltAt=$(TIMESTAMP) \
		" $(cmd_package)

build: $(cmd_target)

endef

$(foreach command,$(commands),$(eval $(call make-go-cmd-target,$(command))))

#
# Generate targets to test Go packages.
#
define make-go-pkg-target
	$(eval pkg_path := $1)
	$(eval pkg_target := $(subst /,-,$(pkg_path)))

coverage-$(pkg_target):
	cd $(SRCDIR) && go test $(pkg_path) -coverprofile=${PROJECTPATH}/cover.out
	cd $(SRCDIR) && go tool cover -html=${PROJECTPATH}/cover.out
	rm cover.out

coverage: coverage-$(pkg_target)

test-$(pkg_target):
	cd $(SRCDIR) && go test $(pkg_path)

test-go: test-$(pkg_target)

endef

$(foreach package,$(packages),$(eval $(call make-go-pkg-target,$(package))))
