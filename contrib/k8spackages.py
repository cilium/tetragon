#!/usr/bin/env python3

import subprocess as sp
from pprint import pprint
import json

def get_package_info(pkg_pattern):
    cmd = ["go", "list", "-json", pkg_pattern]
    cmd = ["sh", "-c", f"go list -json {pkg_pattern} | jq -c"]
    ret = sp.run(cmd, capture_output=True)
    if ret.returncode != 0:
        raise RuntimeError(f'go list error: {ret.stderr}')
    return ret

def main():
    ret = get_package_info("./pkg/...")
    out = ret.stdout
    data = []
    for line in out.splitlines():
        item = json.loads(line)
        path = item['Dir']
        imports = item.get('Imports', [])
        k8s_imports = [x for x in item.get('Imports', []) if "k8s" in x and "sigs.k8s.io/yaml" not in x]
        ## we need to figure out a way tof ix that
        k8s_imports = [x for x in k8s_imports if x != "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"]
        if len(k8s_imports) > 0:
            data.append({'path': path, 'imports': k8s_imports})

    for d in data:
        print(f"{d['path']} => {','.join(d['imports'])}")

if __name__ == '__main__':
    main()
