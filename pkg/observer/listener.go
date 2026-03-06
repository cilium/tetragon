// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"encoding/gob"
	"net"
)

// Channel is a Listener that gob encodes events and sends them to a
// network connection.
type Channel struct {
	conn    net.Conn
	encoder *gob.Encoder
}

// NewChannel initializes Channel.
func NewChannel(conn net.Conn) *Channel {
	return &Channel{
		conn:    conn,
		encoder: gob.NewEncoder(conn),
	}
}

// Notify implements Listener.Notify.
func (o Channel) Notify(msg any) error {
	return o.encoder.Encode(msg)
}

// Close implements Listener.Notify.
func (o Channel) Close() error {
	return o.conn.Close()
}
