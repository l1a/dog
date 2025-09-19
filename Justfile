all: build test
all-release: build-release test-release
all-quick: build-quick test-quick

export DOG_DEBUG := ""


#----------#
# building #
#----------#

# compile the dog binary
@build:
    cargo build

# compile the dog binary (in release mode)
@build-release:
    cargo build --release --verbose
    strip "${CARGO_TARGET_DIR:-target}/release/dog"

# install the dog binary locally (release version)
@install-release:
    cargo install --path .

# produce an HTML chart of compilation timings
@build-time:
    cargo +nightly clean
    cargo +nightly build -Z timings

# compile the dog binary (without some features)
@build-quick:
    cargo build --no-default-features

# check that the dog binary can compile
@check:
    cargo check


#---------------#
# running tests #
#---------------#

# run unit tests
@test:
    cargo test --workspace -- --quiet

# run unit tests (in release mode)
@test-release:
    cargo test --workspace --release --verbose

# run unit tests (without some features)
@test-quick:
    cargo test --workspace --no-default-features -- --quiet

# run mutation tests
@test-mutation:
    cargo +nightly test    --package dns --features=dns/with_mutagen -- --quiet
    cargo +nightly mutagen --package dns --features=dns/with_mutagen


#---------#
# fuzzing #
#---------#

# run fuzzing on the dns crate
@fuzz:
    cargo +nightly fuzz --version
    cd dns; cargo +nightly fuzz run fuzz_parsing -- -jobs=`nproc` -workers=`nproc` -runs=69105

# print out the data that caused crashes during fuzzing as hexadecimal
@fuzz-hex:
    for crash in dns/fuzz/artifacts/fuzz_parsing/crash-*; do echo; echo $crash; hexyl $crash; done

# remove fuzz log files
@fuzz-clean:
    rm dns/fuzz/fuzz-*.log


#-----------------------#
# code quality and misc #
#-----------------------#

# lint the code
@clippy:
    touch dns/src/lib.rs
    cargo clippy

# generate a code coverage report using tarpaulin via docker
@coverage-docker:
    docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin cargo tarpaulin --all --out Html

# update dependency versions, and check for outdated ones
@update-deps:
    cargo update
    command -v cargo-outdated >/dev/null || (echo "cargo-outdated not installed" && exit 1)
    cargo outdated

# list unused dependencies
@unused-deps:
    command -v cargo-udeps >/dev/null || (echo "cargo-udeps not installed" && exit 1)
    cargo +nightly udeps

# print versions of the necessary build tools
@versions:
    rustc --version
    cargo --version


#---------------#
# documentation #
#---------------#

# render the documentation
@doc:
    cargo doc --no-deps --workspace

# build the man pages
@man:
    mkdir -p "${CARGO_TARGET_DIR:-target}/man"
    pandoc --standalone -f markdown -t man man/dog.1.md > "${CARGO_TARGET_DIR:-target}/man/dog.1"

# build and preview the man page
@man-preview: man
    man "${CARGO_TARGET_DIR:-target}/man/dog.1"


#-----------#
# packaging #
#-----------#

# create a distributable package
zip desc exe="dog":
    #!/usr/bin/env perl
    use Archive::Zip;
    -e 'target/release/{{ exe }}' || die 'Binary not built!';
    -e 'target/man/dog.1' || die 'Man page not built!';
    my $zip = Archive::Zip->new();
    $zip->addFile('completions/dog.bash');
    $zip->addFile('completions/dog.zsh');
    $zip->addFile('completions/dog.fish');
    $zip->addFile('target/man/dog.1', 'man/dog.1');
    $zip->addFile('target/release/{{ exe }}', 'bin/{{ exe }}');
    $zip->writeToFileNamed('dog-{{ desc }}.zip') == AZ_OK || die 'Zip write error!';
    system 'unzip -l "dog-{{ desc }}".zip'
