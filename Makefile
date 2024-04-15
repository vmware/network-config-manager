all: build
	ninja -C build
.PHONY: all

build:
	meson setup --prefix=/usr -Dtests=true -Dnftables=true build

clang:
	CC=clang meson setup --prefix=/usr -Dtests=true build-clang; ninja -C build-clang

clean:
	rm -rf build/ build-clang/
.PHONY: clean

install: build
	ninja -C build install
.PHONY: install

install-tests: build
	install build/nmctl-tests /usr/bin
.PHONY: install-tests

format:
	@for f in lib/*.[ch] tool/*.[ch]; do \
		echo $$f; \
		astyle --quiet --options=.astylerc $$f; \
	done
.PHONY: format

install-tree: build
	rm -rf build/install-tree
	DESTDIR=install-tree ninja -C build install
	tree build/install-tree
.PHONY: install-tree
