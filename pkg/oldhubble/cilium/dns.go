// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package cilium

import (
	"net"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/tetragon/pkg/oldhubble/parser/getters"
)

const (
	fqdnCacheRefreshInterval = 5 * time.Minute
)

// FqdnCache defines an interface for caching FQDN info from Cilium.
type FqdnCache interface {
	getters.DNSGetter
	InitializeFrom(entries []*models.DNSLookup)
	AddDNSLookup(epID uint64, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32)
}

// syncFQDNCache regularly syncs DNS lookups from Cilium into our local FQDN
// cache
func (s *State) syncFQDNCache() {
	t0 := 1 * time.Second
	t := t0
	for {
		entries, err := s.ciliumClient.GetFqdnCache()
		if err != nil {
			s.log.WithError(err).Error("Unable to obtain fqdn cache from cilium")
			time.Sleep(t)
			t = 2 * t
			continue
		}
		t = t0

		s.fqdnCache.InitializeFrom(entries)
		s.log.WithField("entries", len(entries)).Debug("Fetched DNS cache from cilium")
		time.Sleep(fqdnCacheRefreshInterval)
	}
}

// consumeLogRecordNotifyChannel consume
func (s *State) consumeLogRecordNotifyChannel() {
	for logRecord := range s.logRecord {
		if logRecord.DNS == nil {
			continue
		}
		switch logRecord.LogRecord.Type {
		case accesslog.TypeResponse:
			epID := logRecord.SourceEndpoint.ID
			if epID == 0 {
				continue
			}
			domainName := logRecord.DNS.Query
			if domainName == "" {
				continue
			}
			ips := logRecord.DNS.IPs
			if ips == nil {
				continue
			}
			lookupTime, err := time.Parse(time.RFC3339Nano, logRecord.Timestamp)
			if err != nil {
				s.log.WithError(err).Warn("Unable to parse timestamp of DNS lookup")
				continue
			}
			s.fqdnCache.AddDNSLookup(epID, lookupTime, domainName, ips, logRecord.DNS.TTL)
		}
	}
}
