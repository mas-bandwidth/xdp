
package main

import (
	"os"
	"net"
	"time"
	"fmt"
	"hash/fnv"
	"encoding/binary"
	"strconv"
	"context"
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

func GeneratePacketHeader(packet []byte, sourceAddress *net.UDPAddr, destAddress *net.UDPAddr) {

	var packetLengthData [2]byte
	binary.LittleEndian.PutUint16(packetLengthData[:], uint16(len(packet)))

	hash := fnv.New64a()
	hash.Write(packet[0:1])
	hash.Write(packet[16:])
	hash.Write(sourceAddress.IP.To4())
	hash.Write(destAddress.IP.To4())
	hash.Write(packetLengthData[:])
	hashValue := hash.Sum64()

	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], uint64(hashValue))

	packet[1] = ((data[6] & 0xC0) >> 6) + 42
	packet[2] = (data[3] & 0x1F) + 200
	packet[3] = ((data[2] & 0xFC) >> 2) + 5
	packet[4] = data[0]
	packet[5] = (data[2] & 0x03) + 78
	packet[6] = (data[4] & 0x7F) + 96
	packet[7] = ((data[1] & 0xFC) >> 2) + 100

	if (data[7] & 1) == 0 {
		packet[8] = 79
	} else {
		packet[8] = 7
	}
	if (data[4] & 0x80) == 0 {
		packet[9] = 37
	} else {
		packet[9] = 83
	}

	packet[10] = (data[5] & 0x07) + 124
	packet[11] = ((data[1] & 0xE0) >> 5) + 175
	packet[12] = (data[6] & 0x3F) + 33

	value := (data[1] & 0x03)
	if value == 0 {
		packet[13] = 97
	} else if value == 1 {
		packet[13] = 5
	} else if value == 2 {
		packet[13] = 43
	} else {
		packet[13] = 13
	}

	packet[14] = ((data[5] & 0xF8) >> 3) + 210
	packet[15] = ((data[7] & 0xFE) >> 1) + 17
}

func main() {

	if len(os.Args) != 3 {
		fmt.Printf("\nUsage: go run client.go <source> <dest>\n\n")
		os.Exit(0)
	}

	sourceAddress := ParseAddress(os.Args[1])
	if sourceAddress.Port == 0 {
		sourceAddress.Port = 30000
	}

	destAddress := ParseAddress(os.Args[2])
	if destAddress.Port == 0 {
		destAddress.Port = 40000
	}

	lc := net.ListenConfig{}

	lp, err := lc.ListenPacket(context.Background(), "udp", "0.0.0.0:30000")
	if err != nil {
		panic(fmt.Sprintf("could not bind socket: %v", err))
	}

	conn := lp.(*net.UDPConn)

	for i := 0; i < 10; i++ {

		packet := make([]byte, 1024)

		GeneratePacketHeader(packet, &sourceAddress, &destAddress)

		fmt.Printf("sent %d byte packet to %s\n", len(packet), destAddress.String())

		conn.WriteToUDP(packet, &destAddress)

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
