#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon


import os
import subprocess
import time

def run_memfd(binary: str) -> None:
    try:
        fd = os.memfd_create("fileless-exec-tetragon")
    except OSError as e:
        print("Failed to create memfd: {0}: {1}".format(e.errno, e.strerror))
        sys.exit()

    os.lseek(fd, 0, os.SEEK_SET)

    with open(binary, mode='rb') as fdinput:
        data = fdinput.read()
        try:
            nbytes = os.write(fd, data)
        except OSError as e:
            print("Failed to write binary into memfd: {0}: {1}".format(e.errno, e.strerror))
            sys.exit()

    print("Copied    {0}  bytes {1}  into memfd {2}".format(binary, nbytes, fd))
    print("Executing {0}  from memfd {1}".format(binary, fd))

    os.execv("/proc/self/fd/%d" % fd, ['fileless-exec-tetragon'])

if __name__ == '__main__':
    run_memfd("/bin/true")
