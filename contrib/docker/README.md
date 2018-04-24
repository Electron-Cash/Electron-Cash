# Docker build environments

Run an environment using:
```
./contrib/docker/setup run <target>
```
or if docker requires root permissions:
```
./contrib/docker/setup run --root <target>
```
Build an image using:
```
./contrib/docker/setup build <target>
```
The available targets are:
```
slim windows android full
```
