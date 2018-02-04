FROM ubuntu:16.04
LABEL maintainer "Marcel O'Neil <marcel@marceloneil.com>"

ARG DEBIAN_FRONTEND="noninteractive"
ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

COPY scripts/* /scripts/
RUN /scripts/base
RUN /scripts/android
RUN rm -r /scripts/

USER electroncash
WORKDIR /repo/
