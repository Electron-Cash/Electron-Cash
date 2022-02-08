AppImage binary for Electron Cash
============================

✓ _This binary is reproducible: you should be able to generate
   binaries that match the official releases (i.e. with the same sha256 hash)._

This assumes an Ubuntu host, but it should not be too hard to adapt to another
similar system. The docker commands should be executed in the project's root
folder.

1. Install Docker  (Ubuntu instructions -- other platforms vary)

    ```
    $ sudo apt update
    $ sudo apt install -y docker.io
    ```

2. Make sure your current user account is in the `docker` group (edit `/etc/groups`, log out, log back in).

3. Build binary

    ```
    $ contrib/build-linux/appimage/build.sh REVISION_TAG_OR_BRANCH_OR_COMMIT_TAG
    ```

4. The generated .AppImage binary is in `./dist`.


## FAQ

### How can I see what is included in the AppImage?
Execute the binary as follows: `./Electron-Cash*.AppImage --appimage-extract`
