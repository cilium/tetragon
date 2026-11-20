---
title: "Correlate additional metadata with events"
weight: 1
description: "Enrich Tetragon events from sources other than the kernel"
---

### Add user names to Tetragon events

From a practical perspective, it can be helpful if Tetragon events ultimately 
bear human-friendly user names in addition to `uid`s and `auid`s. Tetragon sits
very close to (and partly inside) the kernel, which has no knowledge of user
names over these ids.

Hence the addition of user names is best accomplished in a pipeline where
Tetragon comes first and a script dedicated to the task comes second, more
peripheral to the kernel. If a script is not deemed performamt enough, the task
could be carried instead by a binary that would act as gRPC client opposite
Tetragon.

The following example details the script-based approach; it assumes that
Tetragon has been started with option `-export-filename
/var/log/tetragon/tetragon.log`.

```
tail -f /var/log/tetragon/tetragon.log | sudo add-usernames.sh
```

`add-usernames.sh` is as follows:

```
#!/bin/bash
set -e
trap 'echo "error: $0:$LINENO"' ERR

pattern_1='^\{"process_(exec|exit)":\{'
pattern_2='\{"process":\{.*\}, "parent":\{.*"binary":"[^"]*/'$(basename $0)'".*'

while read -r event; do
	# skip Tetragon events other than process_exec, process_exit;
	# for those, avoid "recursion" whereby invocation of an external
	# binary (e.g. jq) would lead to further Tetragon events process_exec,
	# process_exit, which would in turn lead to further invocations
	# of the external binary, etc., etc.; instead employ heuristic that
	# relies on the fact that Tetragon sends its events in compact JSON
	# and with .process before .parent
	if ! [[ "$event" =~ $pattern_1 ]] || [[ "$event" =~ $pattern_2 ]]; then
		continue
	fi

	# extract uid, auid
	echo "$event" | jq -r '. |
		if has("process_exec") then
			.process_exec.process.uid,
			.process_exec.process.auid
		else
			.process_exit.process.uid,
			.process_exit.process.auid
		end' | \
	(
		read uid;
		read auid

		# translate ids into user-friendly names, if possible
		uid_user=$(id -nu $uid 2> /dev/null) || true
		[ -n "$uid_user" ] || uid_user=$uid
  		if [ $uid -eq $auid ]; then
    			user=$uid_user
  		else
			auid_user=$(id -nu $auid 2> /dev/null) || true
			[ -n "$auid_user" ] || auid_user=$uid
    			user="$uid_user ($auid_user)"
  		fi

		# add user name to Teragon event
		echo $event | jq --arg user "$user" '. + {"user":$user}'
	)
done
```
