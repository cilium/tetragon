# Run the POC

From the tetragon root directory, run:

```bash
make kind-setup
# now tetragon should be running in kind

# deploy a simple app with the right deployment label
kubectl apply -f ./poc/test/app.yaml

# Create the template
kubectl apply -f ./poc/test/template.yaml

# Create the binding for the above app deployment
kubectl apply -f ./poc/test/binding1.yaml

# Tetragon in one terminal
kubectl exec -ti -n tetragon ds/tetragon -c tetragon -- tetra getevents -o compact --pods app-1

# Enter the app pod
kubectl exec -ti deploy/app-1 -- bash
```

Now inside the app pod we should receive a notification only when the binary `/usr/bin/nmap` is executed, this is what we defined in the binding1 above.
Running `/usr/bin/nmap` should produce the following output:

```txt
❓ syscall default/app-1-ffd9b9b9b-47wjw /bin/bash security_bprm_creds_for_exec     
🚀 process default/app-1-ffd9b9b9b-47wjw /usr/bin/nmap                    
💥 exit    default/app-1-ffd9b9b9b-47wjw /usr/bin/nmap  255  
```

## Cleanup

```bash
kubectl delete -f ./poc/test/binding1.yaml
kubectl delete -f ./poc/test/template.yaml
kubectl delete -f ./poc/test/app.yaml
make kind-down
```
