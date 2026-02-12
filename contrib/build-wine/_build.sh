#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)
pushd "$here"
here=`pwd`  # get an absolute path
popd

export BUILD_TYPE="wine"
export GCC_TRIPLET_HOST="${GCC_TRIPLET_HOST:-x86_64-w64-mingw32}"
export GCC_TRIPLET_HOST_ARCH="${GCC_TRIPLET_HOST%%-*}"  # e.g. x86_64
# Map GCC arch to Python installer directory name
case "$GCC_TRIPLET_HOST_ARCH" in
    x86_64) export PYTHON_ARCH="amd64" ;;
    i686)   export PYTHON_ARCH="win32" ;;
    *)      echo "Unknown architecture: $GCC_TRIPLET_HOST_ARCH" && exit 1 ;;
esac
export GCC_TRIPLET_BUILD="x86_64-pc-linux-gnu"
export GCC_STRIP_BINARIES="1"
export GIT_SUBMODULE_FLAGS="--recommend-shallow --depth 1"

# On some systems git complains about permissions here. This fixes it.
git config --global --add safe.directory $(readlink -f "$here"/../..)  # /homedir/wine/drive_c/electroncash

. "$here"/../base.sh # functions we use below (fail, et al)

if [ ! -z "$1" ]; then
    to_build="$1"
else
    fail "Please specify a release tag or branch to build (eg: master or 4.0.0, etc)"
fi

set -e

git checkout "$to_build" || fail "Could not branch or tag $to_build"

GIT_COMMIT_HASH=$(git rev-parse HEAD)
VERSION=`git_describe_filtered`

info "Clearing $here/build and $here/dist..."
rm "$here"/build/* -fr
rm "$here"/dist/* -fr

rm -fr /tmp/electrum-build
mkdir -p /tmp/electrum-build

(
    cd "$PROJECT_ROOT"
    for pkg in secp zbar openssl libevent zlib tor ; do
        "$here"/../make_$pkg || fail "Could not build $pkg"
    done
)

prepare_wine() {
    info "Preparing Wine..."
    (
        set -e
        pushd "$here"
        here=`pwd`
        # Please update these carefully, some versions won't work under Wine

        NSIS_URL='https://prdownloads.sourceforge.net/nsis/nsis-3.06.1-setup.exe'
        NSIS_SHA256=f60488a676308079bfdf6845dc7114cfd4bbff47b66be4db827b89bb8d7fdc52

        LIBUSB_REPO='https://github.com/libusb/libusb.git'
        LIBUSB_COMMIT=c6a35c56016ea2ab2f19115d2ea1e85e0edae155 # Version 1.0.24

        PYINSTALLER_REPO='https://github.com/pyinstaller/pyinstaller.git'
        PYINSTALLER_COMMIT=90256f93ed943daf6de53c7dd39710a415f705cb # Version 6.4.0

        ## These settings probably don't need change
        PYHOME=c:/python$PYTHON_VERSION  # NB: PYTON_VERSION comes from ../base.sh
        PYTHON="wine $PYHOME/python.exe -OO -B"

        info "Cleaning tmp"
        rm -rf $HOME/tmp
        mkdir -p $HOME/tmp
        info "done"

        pushd $HOME/tmp

        # note: you might need "sudo apt-get install dirmngr" for the following
        # if the verification fails you might need to get more keys from python.org
        # keys from https://www.python.org/downloads/#pubkeys
        info "Importing Python dev keyring (may take a few minutes)..."
        KEYRING_PYTHON_DEV=keyring-electroncash-build-python-dev.gpg
        gpg -v --no-default-keyring --keyring $KEYRING_PYTHON_DEV --import \
            "$here"/pgp/7ed10b6531d7c8e1bc296021fc624643487034e5.asc \
            || fail "Failed to import Python release signing keys"

        # Install Python
        info "Installing Python ..."
        # dev needs to be after exe, otherwise there is a stack overflow in wine
        msifiles="core exe dev lib pip tools"

        for msifile in $msifiles ; do
            info "Downloading $msifile..."
            wget "https://www.python.org/ftp/python/$PYTHON_VERSION/$PYTHON_ARCH/${msifile}.msi"
            wget "https://www.python.org/ftp/python/$PYTHON_VERSION/$PYTHON_ARCH/${msifile}.msi.asc"
            verify_signature "${msifile}.msi.asc" $KEYRING_PYTHON_DEV
        done

        if [ "$PYTHON_ARCH" = "amd64" ]; then
            $SHA256_PROG -c - << EOF
d5499530d9cddc316811630736eb1bd35f22637f889d562cd3e8e980b1aebd17 core.msi
eb413f9579079f961d3f4c034ba8e00d28ff1cb703f873b9b585c0f467321fba dev.msi
b0a7aaffc9b03d5c7d04d8522e30c5027a8c70ec4c14a6922d6c2cf560bc1459 exe.msi
1e6f5cedc0158f6f2f23d0657d3e6858853569084669dac8f367fc3b94dc4c9b lib.msi
014460c0444bfff5a003ca0a6375c4b41a257f5ed380a714cda3fbcf5d3c1579 pip.msi
6d34cbc645c1b2dd360a0b0df79205b24f0d5f85fea2865f1cc1428d6a64b9cd tools.msi
EOF
        elif [ "$PYTHON_ARCH" = "win32" ]; then
            $SHA256_PROG -c - << EOF
f49a951a6ad7e733e64877b36c8fe43477c2b1c26d316f30a2379bb35a8538a8 core.msi
45c3faeccbd7fa5041f00fea2d05dfcd1a4ef0211aa519508e168b4bcea92bac dev.msi
6b18e724b5ae84df94c3d6cbe55c9143a46802e49c6c7310db7c6e9c1996dc24 exe.msi
6c97ba70fd48747489650b48db5be9ea165dd56f1c6e0ddd5e05c488cf2dd2e2 lib.msi
2a1a5e6adb9d8120c448ab8df8501a16ad419daa93b230c635036f67e4719f5d pip.msi
ee1a5d8ee16eaef3c84c6c4cea4621554d9d1de640fb84ba4f4d982a743fef81 tools.msi
EOF
        fi
        test $? -eq 0 || fail "Failed to verify Python checksums"

        for msifile in $msifiles ; do
            info "Installing $msifile..."
            wine msiexec /i "${msifile}.msi" /qn TARGETDIR=$PYHOME || fail "Failed to install Python component: ${msifile}"
        done

        # The below requirement files use hashed packages that we
        # need for pyinstaller and other parts of the build.  Using a hashed
        # requirements file hardens the build against dependency attacks.
        info "Installing pip from requirements-pip.txt ..."
        $PYTHON -m pip install --no-deps --no-warn-script-location -r $here/../deterministic-build/requirements-pip.txt || fail "Failed to install pip"
        info "Installing build requirements from requirements-build-wine.txt ..."
        $PYTHON -m pip install --no-deps --no-warn-script-location -r $here/../deterministic-build/requirements-build-wine.txt || fail "Failed to install build requirements"

        info "Compiling PyInstaller bootloader with AntiVirus False-Positive Protection™ ..."
        mkdir pyinstaller
        (
            cd pyinstaller
            # Shallow clone
            git init
            git remote add origin $PYINSTALLER_REPO
            git fetch --depth 1 origin $PYINSTALLER_COMMIT
            git checkout -b pinned "${PYINSTALLER_COMMIT}^{commit}"
            rm -fv PyInstaller/bootloader/Windows-*/run*.exe || true  # Make sure EXEs that came with repo are deleted -- we rebuild them and need to detect if build failed
            if [ ${PYI_SKIP_TAG:-0} -eq 0 ] ; then
                echo "const char *ec_tag = \"tagged by Electron-Cash@$GIT_COMMIT_HASH\";" >> ./bootloader/src/pyi_main.c
            else
                warn "Skipping PyInstaller tag"
            fi
            pushd bootloader
            # If switching to 64-bit Windows, edit CC= below
            python3 ./waf all CC="$GCC_TRIPLET_HOST-gcc" CFLAGS="-Wno-stringop-overflow -static"
            # Note: it's possible for the EXE to not be there if the build
            # failed but didn't return exit status != 0 to the shell (waf bug?);
            # So we need to do this to make sure the EXE is actually there.
            popd
            [ -e PyInstaller/bootloader/Windows-32bit-intel/runw.exe -o -e PyInstaller/bootloader/Windows-64bit-intel/runw.exe ] || fail "Could not find runw.exe in target dir!"
            rm -fv pyinstaller.py  # workaround for https://github.com/pyinstaller/pyinstaller/pull/6701
        ) || fail "PyInstaller bootloader build failed"
        info "Installing PyInstaller ..."
        $PYTHON -m pip install --no-deps --no-warn-script-location ./pyinstaller || fail "PyInstaller install failed"

        wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" -v || fail "Pyinstaller installed but cannot be run."

        info "Installing Packages from requirements-binaries ..."
        $PYTHON -m pip install --no-deps --no-warn-script-location -r $here/../deterministic-build/requirements-binaries.txt || fail "Failed to install requirements-binaries"

        info "Installing NSIS ..."
        # Install NSIS installer
        wget -O nsis.exe "$NSIS_URL"
        verify_hash nsis.exe $NSIS_SHA256
        wine nsis.exe /S || fail "Could not run nsis"

        info "Compiling libusb ..."
        mkdir libusb
        (
            cd libusb
            # Shallow clone
            git init
            git remote add origin $LIBUSB_REPO
            git fetch --depth 1 origin $LIBUSB_COMMIT
            git checkout -b pinned "${LIBUSB_COMMIT}^{commit}"
            echo "libusb_1_0_la_LDFLAGS += -Wc,-static" >> libusb/Makefile.am
            ./bootstrap.sh || fail "Could not bootstrap libusb"
            LDFLAGS="-Wl,--no-insert-timestamp" ./configure $AUTOCONF_FLAGS || fail "Could not run ./configure for libusb"
            make -j4 || fail "Could not build libusb"
            host_strip libusb/.libs/libusb-1.0.dll
        ) || fail "libusb build failed"

        # libsecp256k1, libzbar & libusb
        mkdir -p "$WINEPREFIX"/drive_c/tmp
        cp "$here"/../../electroncash/*.dll "$WINEPREFIX"/drive_c/tmp/ || fail "Could not copy libraries to their destination"
        cp libusb/libusb/.libs/libusb-1.0.dll "$WINEPREFIX"/drive_c/tmp/ || fail "Could not copy libusb to its destination"
        cp "$here"/../../electroncash/tor/bin/tor.exe "$WINEPREFIX"/drive_c/tmp/ || fail "Could not copy tor.exe to its destination"

        popd  # out of homedir/tmp
        popd  # out of $here

    ) || fail "Could not prepare Wine"
    info "Wine is configured."
}
prepare_wine

build_the_app() {
    info "Building $PACKAGE ..."
    (
        set -e

        pushd "$here"
        here=`pwd`

        NAME_ROOT=$PACKAGE  # PACKAGE comes from ../base.sh
        # These settings probably don't need any change
        export PYTHONDONTWRITEBYTECODE=1

        PYHOME=c:/python$PYTHON_VERSION
        PYTHON="wine $PYHOME/python.exe -OO -B"

        pushd "$here"/../electrum-locale
        for i in ./locale/*; do
            dir=$i/LC_MESSAGES
            mkdir -p $dir
            msgfmt --output-file=$dir/electron-cash.mo $i/electron-cash.po || true
        done
        popd


        pushd "$here"/../..  # go to top level


        info "Version to release: $VERSION"
        info "Fudging timestamps on all files for determinism ..."
        find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
        popd  # go back to $here

        cp -r "$here"/../electrum-locale/locale "$WINEPREFIX"/drive_c/electroncash/electroncash/

        # Install frozen dependencies
        info "Installing frozen dependencies ..."
        $PYTHON -m pip install --no-deps --no-warn-script-location -r "$here"/../deterministic-build/requirements.txt || fail "Failed to install requirements"
        # Temporary fix for hidapi incompatibility with Cython 3
        # See https://github.com/trezor/cython-hidapi/issues/155
        # We use PIP_CONSTRAINT as an environment variable instead of command line flag because it gets passed to subprocesses
        # like the isolated build environment pip uses for dependencies.
        PIP_CONSTRAINT="$here/../requirements/build-constraint.txt" $PYTHON -m pip install --no-deps --no-warn-script-location -r "$here"/../deterministic-build/requirements-hw.txt || fail "Failed to install requirements-hw"

        pushd "$WINEPREFIX"/drive_c/electroncash
        $PYTHON setup.py install || fail "Failed setup.py install"
        popd

        rm -rf dist/

        info "Resetting modification time in C:\Python..."
        # (Because we just installed a bunch of stuff)
        pushd "$WINEPREFIX"/drive_c/python$PYTHON_VERSION
        find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
        ls -l
        popd

        # build standalone and portable versions
        info "Running Pyinstaller to build standalone and portable .exe versions ..."
        ELECTRONCASH_CMDLINE_NAME="$NAME_ROOT" wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" --noconfirm deterministic.spec || fail "Pyinstaller failed"

        # rename the output files
        pushd dist
        mv $NAME_ROOT.exe $NAME_ROOT-$VERSION-$GCC_TRIPLET_HOST_ARCH.exe
        mv $NAME_ROOT-portable.exe $NAME_ROOT-$VERSION-$GCC_TRIPLET_HOST_ARCH-portable.exe
        popd

        # set timestamps in dist, in order to make the installer reproducible
        pushd dist
        find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
        popd


        # build NSIS installer
        info "Running makensis to build setup .exe version ..."
        # $VERSION could be passed to the electron-cash.nsi script, but this would require some rewriting in the script iself.
        wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION /DGCC_TRIPLET_HOST_ARCH=$GCC_TRIPLET_HOST_ARCH electron-cash.nsi || fail "makensis failed"

        cd dist
        mv $NAME_ROOT-setup.exe $NAME_ROOT-$VERSION-$GCC_TRIPLET_HOST_ARCH-setup.exe  || fail "Failed to move $NAME_ROOT-$VERSION-$GCC_TRIPLET_HOST_ARCH-setup.exe to the output dist/ directory"

        ls -la *.exe
        sha256sum *.exe

        popd

    ) || fail "Failed to build $PACKAGE"
    info "Done building."
}
build_the_app
