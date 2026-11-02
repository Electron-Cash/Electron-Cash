# This image must be built in the context of the repository root.

FROM debian:bookworm-20231009
SHELL ["/bin/bash", "-c"]
WORKDIR /root

RUN apt-get update && \
    apt-get install -y openjdk-17-jdk-headless unzip wget
RUN echo "progress=dot:giga" > .wgetrc

# Install the same minor Python version as Chaquopy uses.
RUN apt-get update && \
    apt-get install -y gcc libbz2-dev libffi-dev liblzma-dev libsqlite3-dev libssl-dev \
                       zlib1g-dev make
                       
RUN version=3.13.9 && \
    wget https://www.python.org/ftp/python/$version/Python-$version.tgz && \
    tar -xf Python-$version.tgz && \
    cd Python-$version && \
    ./configure && \
    make -j $(nproc) && \
    make install && \
    cd .. && \
    rm -r Python-$version*

RUN filename=commandlinetools-linux-13114758_latest.zip && \
    wget https://dl.google.com/android/repository/$filename && \
    mkdir -p android-sdk/cmdline-tools/latest && \
    unzip -q -d /tmp/android-cmdline-tools $filename && \
    mv /tmp/android-cmdline-tools/cmdline-tools/* android-sdk/cmdline-tools/latest/ && \
    rm -rf /tmp/android-cmdline-tools $filename

# Indicate that we accept the Android SDK license. The platform version here isn't critical:
# all versions require the same license, and if app/build.gradle has a different
# compileSdkVersion, the build process will automatically download it.
RUN yes | android-sdk/cmdline-tools/latest/bin/sdkmanager \
    --sdk_root=/root/android-sdk \
    "platforms;android-36" \
    "build-tools;35.0.0" \
    "platform-tools"

# For generate_strings.py.
RUN apt-get update && \
    apt-get install -y gettext
COPY android/build-requirements.txt android/
RUN pip3 install -r android/build-requirements.txt
COPY contrib/make_locale contrib/
COPY electroncash_gui electroncash_gui
COPY ios/ElectronCash/electroncash_gui/ios_native ios/ElectronCash/electroncash_gui/ios_native
COPY electroncash_plugins electroncash_plugins
COPY contrib/electrum-locale contrib/electrum-locale

# The app itself.
COPY android android
COPY contrib/deterministic-build contrib/deterministic-build
COPY electroncash electroncash

RUN echo "sdk.dir=$(pwd)/android-sdk" > android/local.properties
RUN cd android && ./gradlew app:assembleMainNetRelease
