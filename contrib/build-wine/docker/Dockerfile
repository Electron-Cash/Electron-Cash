FROM ubuntu:22.04@sha256:42ba2dfce475de1113d55602d40af18415897167d47c2045ec7b6d9746ff148f

ARG UBUNTU_MIRROR=http://archive.ubuntu.com/ubuntu/

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

ENV UBUNTUDIST=jammy

# This prevents questions during package installations
ENV DEBIAN_FRONTEND=noninteractive

RUN echo deb ${UBUNTU_MIRROR} ${UBUNTUDIST} main restricted universe multiverse > /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} ${UBUNTUDIST}-updates main restricted universe multiverse >> /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} ${UBUNTUDIST}-backports main restricted universe multiverse >> /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} ${UBUNTUDIST}-security main restricted universe multiverse >> /etc/apt/sources.list && \
    dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy \
        gnupg2=2.2.27-3ubuntu2.4 \
        ca-certificates=20211016 \
        wget=1.21.2-2ubuntu1 \
        git=1:2.34.1-1ubuntu1.15 \
        p7zip-full=16.02+dfsg-8 \
        make=4.3-4.1build1 \
        autotools-dev=20220109.1 \
        autoconf=2.71-2 \
        libtool=2.4.6-15build2 \
        gettext=0.21-4ubuntu4 \
        autopoint=0.21-4ubuntu4 \
        mingw-w64=8.0.0-1 \
        mingw-w64-tools=8.0.0-1 \
        win-iconv-mingw-w64-dev=0.0.8-4

# Official WineHQ signing key
# See https://wiki.winehq.org/Ubuntu
# From https://dl.winehq.org/wine-builds/winehq.key
COPY winehq.key /tmp

ENV WINEDIST=devel
ENV WINEVERSION=9.0.0~${UBUNTUDIST}-1

RUN echo "78b185fabdb323971d13bd329fefc8038e08559aa51c4996de18db0639a51df6 /tmp/winehq.key" | sha256sum -c - && \
    cat /tmp/winehq.key | gpg --dearmor -o /etc/apt/keyrings/winehq.gpg && \
    echo deb [signed-by=/etc/apt/keyrings/winehq.gpg] https://dl.winehq.org/wine-builds/ubuntu/ ${UBUNTUDIST} main >> /etc/apt/sources.list.d/winehq.list && \
    apt-get update -q && \
    apt-get install -qy \
        wine-${WINEDIST}-amd64:amd64=${WINEVERSION} \
        wine-${WINEDIST}-i386:i386=${WINEVERSION} \
        wine-${WINEDIST}:amd64=${WINEVERSION} \
        winehq-${WINEDIST}:amd64=${WINEVERSION} \
        # cabextract is needed for winetricks to install the .NET framework
        cabextract=1.9-3 \
        # xvfb is needed to launch the Visual Studio installer
        xvfb=2:21.1.4-2ubuntu1.7~22.04.16 \
        # winbind is needed for the Visual Studio installer and cl.exe PDB generation
        winbind=2:4.15.13+dfsg-0ubuntu1.10

RUN rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

RUN wget -q -O /tmp/winetricks https://raw.githubusercontent.com/Winetricks/winetricks/a9a556719e4fd28fc5984a963e2d666ec809f554/src/winetricks && \
    chmod +x /tmp/winetricks && \
    echo "8127fbe3b6c9c996258e8fc08d05ac72ef11cb1465c5fe0d13e9d28580ba99a7 /tmp/winetricks" | sha256sum -c -

ARG USER_ID
ARG GROUP_ID

ENV HOME=/homedir
ENV WINEARCH=win32
ENV WINEPREFIX=${HOME}/wine
ENV WINEDEBUG=-all

RUN mkdir -p ${WINEPREFIX}/drive_c/electroncash ; chown -R ${USER_ID}:${GROUP_ID} ${HOME}

# Make our UID/GID have an actual user name, this is needed so wineboot creates the right folders and
# the Visual Studio installer does't fail in SHGetKnownFolderPath with error 0x80070003 (ERROR_PATH_NOT_FOUND).
RUN echo "user:x:${USER_ID}:${GROUP_ID}::${HOME}:/bin/sh" >> /etc/passwd
USER ${USER_ID}:${GROUP_ID}

WORKDIR ${HOME}

# wineboot needs to run after the user is added to /etc/passwd, otherwise it will assume the username is "wine"
RUN wineboot && \
    /tmp/winetricks --optout -q dotnet472 && \
    # Wait for the wine server to shutdown, needs to be done after wineboot to ensure the installation is good
    wineserver -w

# DBUS_FATAL_WARNINGS=0 is needed because we don't have dbus in the container and Wine calls
# dbus_connection_send_with_reply_and_block with a NULL connection. The dbus client libraries are set to abort by
# default unless this variable is set.
ENV DBUS_FATAL_WARNINGS=0

RUN wget https://aka.ms/vs/16/release/installer -O /tmp/vs_installer.opc && \
    # As of 2023-10-09 the checksum has changed and is not the same as in winetricks anymore
    echo "0f0cc11f000593a064d419462a8467b529fed8075b21a605a40785baa3d2f611 /tmp/vs_installer.opc" | sha256sum -c - && \
    7z x -oopc /tmp/vs_installer.opc && rm /tmp/vs_installer.opc && \
    xvfb-run wine opc/Contents/vs_installer.exe install --quiet \
        --channelId VisualStudio.16.Release --channelUri "https://aka.ms/vs/16/release/channel" \
        --productId Microsoft.VisualStudio.Product.BuildTools \
        --nocache --installWhileDownloading \
        --add "Microsoft.VisualStudio.Workload.VCTools" \
        # We could use --includeRecommended like winetricks does but to save time and space we only include what we actually need
        --add "Microsoft.VisualStudio.Component.VC.Tools.x86.x64" \
        --add "Microsoft.VisualStudio.Component.Windows10SDK.19041" && \
    # vswhere.exe needs to be installed in this path so setuptools can detect the VS installation
    mkdir "${WINEPREFIX}"/"drive_c/Program Files/Microsoft Visual Studio/Installer" && \
    mv opc/Contents/vswhere.exe "${WINEPREFIX}"/"drive_c/Program Files/Microsoft Visual Studio/Installer" && \
    rm -rf opc && wineserver -w

#RUN wine "${WINEPREFIX}"/"drive_c/windows/Microsoft.NET/Framework/v4.0.30319/ngen.exe" executequeueditems && \
#    wineserver -w

# Patch to make vcvarsall.bat work
# "C:\Program Files\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86 && set
# python -c "from setuptools import msvc; print(msvc.msvc14_get_vc_env('x86'))"
# Caused by wrong delayed expansion in Wine, see https://bugs.winehq.org/show_bug.cgi?id=38289
RUN sed -i -e 's/!result:~0,3!/10./g' "${WINEPREFIX}"/"drive_c/Program Files/Microsoft Visual Studio/2019/BuildTools/Common7/Tools/vsdevcmd/core/winsdk.bat"

# Clean up some left overs only needed for the Visual Studio installer
USER 0:0
RUN apt-get remove cabextract xvfb -y && \
    apt-get autoremove -y
USER ${USER_ID}:${GROUP_ID}

# Build a wrapper for MSVC's link.exe that always passes the /Brepro flag to ensure builds are reproducible.
COPY wrapper.cpp ${WINEPREFIX}/drive_c
COPY wrapper_install.bat ${WINEPREFIX}/drive_c
RUN wine C:/wrapper_install.bat && \
    wineserver -w
