FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y \
    make \
    clang \
    llvm \
    libelf-dev \
    libyara-dev \
    pkg-config \
    git \
    flex \
    bison

WORKDIR /tetragon
