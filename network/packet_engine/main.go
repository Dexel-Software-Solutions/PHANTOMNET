// PHANTOMNET — Go Packet Engine
// High-performance packet capture and parsing.
// Outputs JSON-lines to stdout for the Python orchestrator.
//
// Build: go build -o bin/pktengine main.go
// Requires: libpcap-dev

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketMeta is the JSON structure sent to Python per packet.
type PacketMeta struct {
	SrcIP    string   `json:"src_ip"`
	DstIP    string   `json:"dst_ip"`
	SrcPort  uint16   `json:"src_port"`
	DstPort  uint16   `json:"dst_port"`
	Protocol string   `json:"protocol"`
	Flags    []string `json:"flags"`
	Length   int      `json:"length"`
	Timestamp int64   `json:"timestamp"`
}

func tcpFlags(tcp *layers.TCP) []string {
	flags := []string{}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	return flags
}

func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func main() {
	iface := flag.String("interface", "eth0", "Network interface to capture on")
	format := flag.String("format", "json", "Output format (json only)")
	snapLen := flag.Int("snaplen", 65535, "Snapshot length")
	flag.Parse()

	if *format != "json" {
		fmt.Fprintln(os.Stderr, "[pktengine] Only json format is supported")
		os.Exit(1)
	}

	// Verify interface exists
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("[pktengine] Cannot enumerate interfaces: %v", err)
	}
	found := false
	for _, i := range ifaces {
		if i.Name == *iface {
			found = true
			break
		}
	}
	if !found {
		log.Fatalf("[pktengine] Interface '%s' not found", *iface)
	}

	handle, err := pcap.OpenLive(*iface, int32(*snapLen), true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("[pktengine] Failed to open interface %s: %v", *iface, err)
	}
	defer handle.Close()

	// Only capture IP traffic
	if err := handle.SetBPFFilter("ip"); err != nil {
		log.Fatalf("[pktengine] BPF filter error: %v", err)
	}

	fmt.Fprintf(os.Stderr, "[pktengine] Capturing on %s\n", *iface)

	encoder := json.NewEncoder(os.Stdout)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "[pktengine] Shutting down...")
		handle.Close()
		os.Exit(0)
	}()

	for packet := range packetSource.Packets() {
		meta := PacketMeta{
			Length:    packet.Metadata().Length,
			Timestamp: time.Now().UnixMilli(),
		}

		// Extract IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		meta.SrcIP = ip.SrcIP.String()
		meta.DstIP = ip.DstIP.String()

		// Skip loopback
		if ip.SrcIP.IsLoopback() || ip.DstIP.IsLoopback() {
			continue
		}

		// TCP
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			meta.Protocol = "TCP"
			meta.SrcPort = uint16(tcp.SrcPort)
			meta.DstPort = uint16(tcp.DstPort)
			meta.Flags = tcpFlags(tcp)
		}

		// UDP
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			meta.Protocol = "UDP"
			meta.SrcPort = uint16(udp.SrcPort)
			meta.DstPort = uint16(udp.DstPort)
		}

		// ICMP
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpLayer != nil {
			meta.Protocol = "ICMP"
		}

		if meta.Protocol == "" {
			continue
		}

		if err := encoder.Encode(meta); err != nil {
			fmt.Fprintf(os.Stderr, "[pktengine] Encode error: %v\n", err)
		}
	}
}
