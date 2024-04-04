
package main

import (
	"net"
	"time"
	"fmt"
	"strconv"
	"context"
	"crypto/rand"
)

func ParseAddress(input string) net.UDPAddr {
	address := net.UDPAddr{}
	ip_string, port_string, err := net.SplitHostPort(input)
	if err != nil {
		address.IP = net.ParseIP(input)
		address.Port = 0
		return address
	}
	address.IP = net.ParseIP(ip_string)
	address.Port, _ = strconv.Atoi(port_string)
	return address
}

func main() {

	// todo: read address from command line
	address := ParseAddress("127.0.0.1:40000")
	if address.Port == 0 {
		address.Port = 40000
	}

	lc := net.ListenConfig{}

	lp, err := lc.ListenPacket(context.Background(), "udp", "0.0.0.0:30000")
	if err != nil {
		panic(fmt.Sprintf("could not bind socket: %v", err))
	}

	conn := lp.(*net.UDPConn)

	for i := 0; i < 10; i++ {

		packet := make([]byte, 256 )

		rand.Read(packet)

		fmt.Printf("sent %d byte packet to %s\n", len(packet), address.String())

		conn.WriteToUDP(packet, &address)

		time.Sleep(time.Millisecond*100)
	}

	for {

		buffer := make([]byte, 1384)

		size, from, err := conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		fmt.Printf("received %d byte packet from %s\n", size, from.String())
	}
}
