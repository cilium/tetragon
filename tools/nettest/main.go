package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	proto := flag.String("proto", "tcp", "Protocol: tcp or udp")
	addr := flag.String("addr", "127.0.0.1:9999", "Target address")
	count := flag.Int("count", 5, "Number of packets to send")
	delay := flag.Duration("delay", 100*time.Millisecond, "Delay between packets")
	server := flag.Bool("server", false, "Run as server instead of client")
	flag.Parse()

	if *server {
		runServer(*proto, *addr)
	} else {
		runClient(*proto, *addr, *count, *delay)
	}
}

func runClient(proto, addr string, count int, delay time.Duration) {
	conn, err := net.Dial(proto, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dial error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("[%s] Connected to %s\n", proto, addr)

	for i := 1; i <= count; i++ {
		msg := fmt.Sprintf("packet-%d", i)
		_, err := conn.Write([]byte(msg))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[%s] Sent: %s\n", proto, msg)
		time.Sleep(delay)
	}

	fmt.Printf("[%s] Done, closing connection\n", proto)
}

func runServer(proto, addr string) {
	if proto == "udp" {
		runUDPServer(addr)
	} else {
		runTCPServer(addr)
	}
}

func runTCPServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Listen error: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Printf("[tcp] Listening on %s\n", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
			continue
		}
		go handleTCP(conn)
	}
}

func handleTCP(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		fmt.Printf("[tcp] Received: %s\n", buf[:n])
	}
}

func runUDPServer(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListenPacket error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("[udp] Listening on %s\n", addr)

	buf := make([]byte, 1024)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ReadFrom error: %v\n", err)
			continue
		}
		fmt.Printf("[udp] Received from %s: %s\n", remote, buf[:n])
	}
}
