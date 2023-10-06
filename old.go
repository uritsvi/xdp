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
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type packet bpf xdp.c -- -I headers

func main() {
	log.Print(unsafe.Sizeof(bpfPacket{}))

	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}
	ops := ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: 3}}

	if err := loadBpfObjects(&objs, &ops); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	chanel := make(chan *bpfPacket)
	memPool := sync.Pool{New: func() any { return new(bpfPacket) }}
	for i := 0; i < 1000; i++ {
		memPool.Get()
	}

	go ProcessData(chanel, &memPool)

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatal("Failed to create a ring buffer reader")
	}

	for {
		packet := memPool.Get().(*bpfPacket)
		record, err := rd.Read()
		if err != nil {
			log.Fatal("Failed to read from ring buffer")
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), internal.NativeEndian, packet); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		println("packet %d", packet.PayloadSize)

		//chanel <- packet
	}
}

func NetToHostShort(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

func ParsIp(i uint32) string {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, i)

	s := fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])

	return s
}

func ProcessData(chanel chan *bpfPacket, memPool *sync.Pool) {
	for {

		packet := <-chanel

		log.Printf(
			"\npacket send\nfrom:\t%s:%d\nto:\t%s:%d\npayload: %s\nsize: %d\n\n",
			ParsIp(packet.Src),
			NetToHostShort(packet.SrcPort),
			ParsIp(packet.Dest),
			NetToHostShort(packet.DestPort),
			B2S(packet.Payload[0:packet.PayloadSize]),
			packet.PayloadSize,
		)

		memPool.Put(packet)
	}

}

func B2S(bs []int8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}
	return string(b)
}
