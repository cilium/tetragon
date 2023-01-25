# Linux Binary tarball

For Linux Binary tarball, files will reside in /usr/local/

Tarball should contain:

1. tetragon.service:
   ```
   /usr/lib/systemd/system/tetragon.service
   ```

2. linux-tarball/usr => /usr/

3. linux-tarball/etc => /etc/

4. Binaries:
   ```
   tetragon => /usr/local/bin/
   tetra    => /usr/local/bin/
   ```

5. Helper Binaries:
   ```
   bpftool	=> /usr/local/lib/tetragon/bpftool
   ```

6. BPF files:
   ```
   /usr/local/lib/tetragon/bpf
   ```
