// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package glob

type TestCase struct {
	Pattern string
	Path    string
	Match   bool
}

var GlobTestCases = []TestCase{
	{Pattern: "/home/*/.bash*", Path: "/home/user/.bash_profile", Match: true},
	{Pattern: "home/*/.bash*", Path: "/home/user/.bash_profile", Match: false},
	{Pattern: "*.txt", Path: "/home/.bash_profile.txt", Match: true},
	{Pattern: "*.txt", Path: "tasos.txta", Match: false},
	{Pattern: "/home/*/.bash*", Path: "/home/user/.bas_profile/.bash_profile", Match: true},
	{Pattern: "*.*", Path: "test.txt", Match: true},
	{Pattern: "*.*", Path: "test", Match: false},
	{Pattern: "/home/*/.bash*t", Path: "/home/user/.bas_profile/.bash_profilea/.bash_profilet", Match: true},
	{Pattern: "*abcd*", Path: "qabczabuuuuabcde", Match: true},
	{Pattern: "a*b*ab", Path: "aabaabaab", Match: true},
	{Pattern: "a*", Path: "aabaabaab", Match: true},
	{Pattern: "aa*", Path: "aabaabaab", Match: true},
	{Pattern: "aaba*", Path: "aabaabaab", Match: true},
	{Pattern: "*d", Path: "abcdd", Match: true},
	{Pattern: "*d*", Path: "abcdd", Match: true},
	{Pattern: "a*baab", Path: "aabaabqqbaab", Match: true},
	{Pattern: "/foo/*/blig", Path: "/foo/bar/baz/xlig/fig/blig", Match: true},
	{Pattern: "/foo/*/blig", Path: "/foo/bar/baz/blig/fig/blig", Match: true},
	{Pattern: "a*baab", Path: "aabaabaab", Match: true},
	{Pattern: "*.txt", Path: "a.tx.txt", Match: true},
	{Pattern: "*", Path: "a.tx.txt", Match: true},
	{Pattern: "*", Path: "ababa", Match: true},
	{Pattern: "*a*b*c*d*e*f*g", Path: "ababadlufgasijkldhfgakljhsdgfjklagsdkfjlhhagsdkjfghasdkjfgakjsdhgfkajsdgfkayueirgfjkhzsdvbcajkhgdevfrkjuyagvda", Match: false},
	{Pattern: "?", Path: "a", Match: true},
	{Pattern: "?", Path: "aa", Match: false},
	{Pattern: "a?a", Path: "aba", Match: true},
	{Pattern: "a?a", Path: "abba", Match: false},
	{Pattern: "a?a*", Path: "abadsafgadsjkhfgahsjk", Match: true},
	{Pattern: "*.t?t", Path: "test.txt", Match: true},
	{Pattern: "*.t?t", Path: "test.tat", Match: true},
	{Pattern: "*.t?t", Path: "test.txxt", Match: false},
	{Pattern: "*.t?t", Path: "test.tx", Match: false},
	{Pattern: "a*b?c", Path: "aabcc", Match: true},
	{Pattern: "a*b?c", Path: "aabbcc", Match: true},
	{Pattern: "a*b?c", Path: "abc", Match: false},
	{Pattern: "a*b?c", Path: "aabbbc", Match: true},
	{Pattern: "a*b?c", Path: "aabbbbc", Match: true},
	{Pattern: "/home/user/.cache/go-build/*.go", Path: "/usr/local/go/src/math/j0.go", Match: false},
	{Pattern: "a*", Path: "a", Match: true},
	{Pattern: "a*b", Path: "ab", Match: true},
	{Pattern: "*a", Path: "a", Match: true},
	{Pattern: "a*?boo", Path: "axboo", Match: true},

	// Character classes.
	{Pattern: "config[0-9].yaml", Path: "config0.yaml", Match: true},
	{Pattern: "config[0-9].yaml", Path: "config9.yaml", Match: true},
	{Pattern: "config[0-9].yaml", Path: "config10.yaml", Match: false},
	{Pattern: "config[0-9].yaml", Path: "configa.yaml", Match: false},
	{Pattern: "config[!0-9].yaml", Path: "configa.yaml", Match: true},
	{Pattern: "config[!0-9].yaml", Path: "config5.yaml", Match: false},
	{Pattern: "file[._-]bak", Path: "file.bak", Match: true},
	{Pattern: "file[._-]bak", Path: "file_bak", Match: true},
	{Pattern: "file[._-]bak", Path: "file-bak", Match: true},
	{Pattern: "file[._-]bak", Path: "filexbak", Match: false},
	{Pattern: "[a-c][0-2]", Path: "a0", Match: true},
	{Pattern: "[a-c][0-2]", Path: "c2", Match: true},
	{Pattern: "[a-c][0-2]", Path: "d2", Match: false},
	{Pattern: "[a-c][0-2]", Path: "c3", Match: false},

	// Brace alternatives for temporary and backup files.
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.TEMP", Match: true},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.backup", Match: true},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.bak", Match: true},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.old", Match: true},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.tar.gz", Match: true},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.tgz", Match: true},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.temp", Match: true},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.tmp", Match: true},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.gz", Match: false},
	{Pattern: "*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}", Path: "/tmp/rules.tmp.more", Match: false},
	{Pattern: "/{bin,etc,lib,lib64,opt,sbin,usr}/*", Path: "/bin/sh", Match: true},
	{Pattern: "/{bin,etc,lib,lib64,opt,sbin,usr}/*", Path: "/etc/passwd", Match: true},
	{Pattern: "/{bin,etc,lib,lib64,opt,sbin,usr}/*", Path: "/lib/modules/kernel", Match: true},
	{Pattern: "/{bin,etc,lib,lib64,opt,sbin,usr}/*", Path: "/lib64/libc.so", Match: true},
	{Pattern: "/{bin,etc,lib,lib64,opt,sbin,usr}/*", Path: "/opt/app/config", Match: true},
	{Pattern: "/{bin,etc,lib,lib64,opt,sbin,usr}/*", Path: "/sbin/init", Match: true},
	{Pattern: "/{bin,etc,lib,lib64,opt,sbin,usr}/*", Path: "/usr/bin/bash", Match: true},
	{Pattern: "/{bin,etc,lib,lib64,opt,sbin,usr}/*", Path: "/root/.ssh/authorized_keys", Match: false},
	{Pattern: "/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*", Path: "/srv/bin/sh", Match: true},
	{Pattern: "/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*", Path: "/srv/etc/config", Match: true},
	{Pattern: "/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*", Path: "/srv/lib/libfoo.so", Match: true},
	{Pattern: "/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*", Path: "/srv/lib64/libfoo.so", Match: true},
	{Pattern: "/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*", Path: "/srv/home/user/.ssh/authorized_keys", Match: true},
	{Pattern: "/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*", Path: "/srv/sbin/init", Match: true},
	{Pattern: "/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*", Path: "/srv/usr/bin/bash", Match: true},
	{Pattern: "/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*", Path: "/srv/home/user/authorized_keys", Match: false},

	// Combined brace alternatives and character classes used for rotated logs.
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.1", Match: true},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.9", Match: true},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.10", Match: true},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.19", Match: true},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.20", Match: true},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.gz", Match: true},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.0", Match: false},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.21", Match: false},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.100", Match: false},
	{Pattern: "/var/log/*.{[1-9],1[0-9],20,gz}", Path: "/var/log/messages.GZ", Match: false},
}

type TestCaseMulti struct {
	Patterns map[string][]int32
	Tests    []struct {
		Path   string
		Values []int32
	}
}

var GlobTestCasesMulti = []TestCaseMulti{
	{
		Patterns: map[string][]int32{
			"abc*":    {1, 3},
			"a?c":     {2},
			"a[cd]b":  {6},
			"a[!cd]c": {8},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "abc", Values: []int32{1, 2, 3, 8}},
			{Path: "acb", Values: []int32{6}},
			{Path: "azc", Values: []int32{2, 8}},
			{Path: "pizza", Values: []int32{}},
		},
	},
	{
		Patterns: map[string][]int32{
			"foo*":   {1},
			"*bar":   {2},
			"foobar": {3},
			"f*r":    {4},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "foobar", Values: []int32{1, 2, 3, 4}},
			{Path: "foor", Values: []int32{1, 4}},
			{Path: "fbar", Values: []int32{2, 4}},
		},
	},
	{
		Patterns: map[string][]int32{
			"*":  {100}, // Match everything
			"":   {200}, // Match only empty string
			"a*": {300},
			"*z": {400},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "", Values: []int32{100, 200}},
			{Path: "az", Values: []int32{100, 300, 400}},
			{Path: "supercalifragilistic", Values: []int32{100}},
		},
	},
	{
		Patterns: map[string][]int32{
			"id-[a-f]":   {1}, // Matches id-a, id-b, ... id-f
			"val-[2-9]":  {2}, // Matches val-0 to val-9
			"val-[!0-5]": {3},
			"val-[01]":   {4},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "id-c", Values: []int32{1}},
			{Path: "id-g", Values: []int32{}},
			{Path: "val-0", Values: []int32{4}},
			{Path: "val-1", Values: []int32{4}},
			{Path: "val-2", Values: []int32{2}},
			{Path: "val-3", Values: []int32{2}},
			{Path: "val-4", Values: []int32{2}},
			{Path: "val-5", Values: []int32{2}},
			{Path: "val-6", Values: []int32{2, 3}},
			{Path: "val-7", Values: []int32{2, 3}},
			{Path: "val-8", Values: []int32{2, 3}},
			{Path: "val-9", Values: []int32{2, 3}},
		},
	},
	{
		Patterns: map[string][]int32{
			"*.{TEMP,backup,bak,old,tar.gz,tgz,temp,tmp}":        {1},
			"/var/log/*.{[1-9],1[0-9],20,gz}":                    {2},
			"/{bin,etc,lib,lib64,opt,sbin,usr}/*":                {3},
			"/srv/{bin,etc,lib,lib64,home/user/.ssh,sbin,usr}/*": {4},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "/tmp/rules.tmp", Values: []int32{1}},
			{Path: "/var/log/messages.gz", Values: []int32{2}},
			{Path: "/var/log/messages.9", Values: []int32{2}},
			{Path: "/var/log/messages.19", Values: []int32{2}},
			{Path: "/var/log/messages.21", Values: []int32{}},
			{Path: "/opt/app/config", Values: []int32{3}},
			{Path: "/srv/usr/bin/bash", Values: []int32{4}},
			{Path: "/srv/home/user/.ssh/authorized_keys", Values: []int32{4}},
			{Path: "/srv/home/user/authorized_keys", Values: []int32{}},
		},
	},
}
