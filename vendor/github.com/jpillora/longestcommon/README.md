# longestcommon

Find the longest common prefix/suffix across of list of strings in Go (Golang). Runs in `O(n)`.

[![GoDoc](https://godoc.org/github.com/jpillora/longestcommon?status.svg)](https://godoc.org/github.com/jpillora/longestcommon) [![Circle CI](https://circleci.com/gh/jpillora/longestcommon.svg?style=shield)](https://circleci.com/gh/jpillora/longestcommon)

### Install

```
$ go get -v github.com/jpillora/longestcommon
```

### Usage

``` go
longestcommon.Prefix([]string{"flower","flow","fleet"}) //"fl"
longestcommon.Suffix([]string{"flower","power","lower"}) //"ower"
```

### TODO

* Include [Longest Common Subsequence](https://github.com/jpillora/lcs) with its TODOs completed

#### MIT License

Copyright © 2015 Jaime Pillora &lt;dev@jpillora.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
