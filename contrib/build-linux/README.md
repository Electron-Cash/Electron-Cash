Source tarballs
===============

1. To create the source tarball (with the libsecp library included):

    ```
    $ contrib/make_linux_sdist
    ```

2. A `.tar.gz` and a `.zip` file of Electron Cash will be placed in the `dist/` subdirectory.


AppImage
===============

1. To create a deterministic Linux AppImage (standalone bundle):

    ```
    $ contrib/build-linux/appimage/build.sh COMMIT_OR_TAG
    ```

    Where `COMMIT_OR_TAG` is a git commit or branch or tag.

2. The built stand-alone Linux program will be placed in `dist/`.

3. The above requires docker.  See [appimage/README.md](appimage/README.md).
