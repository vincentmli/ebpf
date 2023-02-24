// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I../headers

const (
	bpfFSPath = "/sys/fs/bpf"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	mapName := "denylist"
	progName := "denyProg"

	pinPath := path.Join(bpfFSPath, mapName)
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin the map to the BPF filesystem and configure the
			// library to automatically re-write it in the BPF
			// program so it can be re-used if it already exists or
			// create it if not
			PinPath: pinPath,
		},
	}); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	//from: https://xiongliuhua.com/ebpf/201/
	dropIP := []string{"192.168.1.0/24", "127.0.0.0/16"}
	for index, ip := range dropIP {
		//for _, ip := range dropIP {

		if !strings.Contains(ip, "/") {

			ip += "/32"

		}
		_, ipnet, err := net.ParseCIDR(ip)

		if err != nil {

			log.Printf("malformed ip %v \n", err)

			continue
		}
		var res = make([]byte, objs.XdpDenylistMap.KeySize())

		ones, _ := ipnet.Mask.Size()

		binary.LittleEndian.PutUint32(res, uint32(ones))

		copy(res[4:], ipnet.IP)
		if err := objs.XdpDenylistMap.Put(res, uint32(index)); err != nil {
			//	if err := objs.XdpDenylistMap.Delete(res); err != nil {

			log.Fatalf("blacklist put err %v \n", err)

		}
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	err = l.Pin(progName)
	if err != nil {
		log.Fatalf("could not pin XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.XdpStatsMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key []byte
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := net.IP(key) // IPv4 source address in network byte order.
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))
	}
	return sb.String(), iter.Err()
}
