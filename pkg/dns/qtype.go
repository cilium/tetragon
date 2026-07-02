// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package dns

import "strconv"

var qtypeNames = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	13:  "HINFO",
	15:  "MX",
	16:  "TXT",
	17:  "RP",
	18:  "AFSDB",
	24:  "SIG",
	25:  "KEY",
	28:  "AAAA",
	29:  "LOC",
	33:  "SRV",
	35:  "NAPTR",
	37:  "CERT",
	39:  "DNAME",
	41:  "OPT",
	43:  "DS",
	44:  "SSHFP",
	46:  "RRSIG",
	47:  "NSEC",
	48:  "DNSKEY",
	50:  "NSEC3",
	51:  "NSEC3PARAM",
	52:  "TLSA",
	53:  "SMIMEA",
	59:  "CDS",
	60:  "CDNSKEY",
	61:  "OPENPGPKEY",
	64:  "SVCB",
	65:  "HTTPS",
	257: "CAA",
}

// QTypeString returns the IANA mnemonic, or "TYPEn" per RFC 3597 for unknowns.
func QTypeString(t uint16) string {
	if name, ok := qtypeNames[t]; ok {
		return name
	}
	return "TYPE" + strconv.FormatUint(uint64(t), 10)
}
