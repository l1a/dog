# COPR invokes this as: make -f .copr/Makefile srpm outdir=<dir>
#
# COPR runs this inside MOCK, not a plain container, and mock redefines rpm's %{_topdir} to
# /builddir/build. A recipe that copies into $(HOME)/rpmbuild/SPECS works in a plain container
# and fails under mock with 'No such file or directory', so verifying one in a container proves
# nothing about COPR. This recipe points _sourcedir and _srcrpmdir explicitly and depends on
# neither %{_topdir} nor $(HOME).
#
# packaging/copr/dog.spec is a TEMPLATE: its version comes from Cargo.toml in this checkout (via
# scripts/render_packaging.py) and its Source0 is an archive of this checkout. Neither needs a
# published tag or a network fetch, which is what lets a PR build its own SRPM.
#
# The archive is `git archive` when there is a repository to ask, plain `tar` otherwise (whether
# mock's buildroot carries .git is not something this repo can verify without a COPR build, so
# both work, and the recipe PRINTS which path it took). The fallback needs explicit excludes
# written WITHOUT a leading ./ -- GNU tar's --exclude=./target anchors at the top level and
# silently keeps a nested target/.
#
# An SRPM is published and cannot be recalled, so the checks below are hard failures: nothing
# private may ship, and the files whose ABSENCE would be just as bad must be present (no
# Cargo.lock means unpinned resolution, no LICENSE means a GPL obligation unmet, no man page
# source means the %build step fails deep inside rpmbuild instead of here).

SPEC_IN := packaging/copr/dog.spec
BUILD   := $(CURDIR)/.copr-build
RENDER  := scripts/render_packaging.py

.PHONY: srpm

srpm:
	# python3 is in every Fedora buildroot (rpm depends on it) and git usually is not. Both are
	# installed explicitly so a build that fails for a missing tool says so at its first step.
	dnf -y install rpm-build python3 git
	rm -rf $(BUILD)
	mkdir -p $(BUILD) $(outdir)
	V=$$(python3 $(RENDER) --print-version); \
	echo "version from Cargo.toml: $$V"; \
	python3 $(RENDER) --target copr --version "$$V" --out $(BUILD)/dog.spec; \
	TARBALL=$(BUILD)/dog-$$V.tar.gz; \
	if git rev-parse --git-dir >/dev/null 2>&1; then \
	    echo "source: git archive HEAD (the committed tree)"; \
	    git archive --format=tar.gz --prefix="dog-$$V/" -o "$$TARBALL" HEAD; \
	else \
	    echo "source: tar of the working tree (no git repository here)"; \
	    tar --exclude=.git --exclude=target --exclude=.copr-build \
	        --exclude=.claude --exclude=__pycache__ --exclude='*.pyc' \
	        --transform "s,^[.],dog-$$V," \
	        -czf "$$TARBALL" .; \
	fi; \
	tar -tzf "$$TARBALL" > $(BUILD)/listing.txt; \
	echo "packed $$(wc -l < $(BUILD)/listing.txt) entries as dog-$$V/"; \
	if grep -qE "^dog-[^/]+/(target/|[.]git/|[.]claude/|[.]copr-build/)" $(BUILD)/listing.txt; then \
	    echo "error: the source archive contains files that must never ship:" >&2; \
	    grep -E "^dog-[^/]+/(target/|[.]git/|[.]claude/|[.]copr-build/)" $(BUILD)/listing.txt >&2; \
	    exit 1; \
	fi; \
	for f in Cargo.toml Cargo.lock LICENSE README.md build.rs man/dog.1.md src/main.rs; do \
	    grep -qx "dog-$$V/$$f" $(BUILD)/listing.txt \
	        || { echo "error: the source archive is missing $$f" >&2; exit 1; }; \
	done; \
	echo "source archive verified"
	rpmbuild -bs --define '_sourcedir $(BUILD)' --define '_srcrpmdir $(outdir)' $(BUILD)/dog.spec
