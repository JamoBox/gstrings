package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var Version string = "1.0.0"

func is_printable(a uint8) bool {
	return ((uint8)((a)-0x20) <= (0x7e - 0x20))
}

func show_printable(pkt gopacket.Packet, matchlen int) {
	if app := pkt.ApplicationLayer(); app != nil {
		pstr := string(app.Payload())

		var (
			str   []byte
			count int = 0
		)
		for i := 0; i < len(pstr); i++ {
			if is_printable(pstr[i]) || pstr[i] == '\t' {
				if count > matchlen {
					fmt.Printf("%c", pstr[i])
				} else {
					str = append(str, pstr[i])

					if count == matchlen {
						network := pkt.NetworkLayer().NetworkFlow()
						transport := pkt.TransportLayer().TransportFlow()
						nsrc, ndst := network.Endpoints()
						tsrc, tdst := transport.Endpoints()
						fmt.Printf(
							"[%s:%s → %s:%s (%s)]: ",
							nsrc, tsrc, ndst, tdst,
							transport.EndpointType(),
						)
						str = append(str, 0)
						fmt.Printf("%s", string(str[:count+1]))
					}
					count++
				}
			} else {
				if count > matchlen {
					fmt.Printf("\n")
				}
				count = 0
			}
		}

		if count > matchlen {
			fmt.Printf("\n")
		}
	}
}

func main() {
	var show_ver = flag.Bool("v", false, "Display version")
	var match_len = flag.Int("n", 10, "Number of consecutive printable characters")

	flag.Parse()

	if *show_ver {
		fmt.Printf("Version %s\n", Version)
		return
	}

	if len(flag.Args()) < 1 {
		fmt.Println("usage: gstrings <pcap> [-n 10]")
		return
	}

	fd, err := pcap.OpenOffline(flag.Args()[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	pktSrc := gopacket.NewPacketSource(fd, fd.LinkType())

	fmt.Printf("%d", match_len)

	for pkt := range pktSrc.Packets() {
		show_printable(pkt, *match_len)
	}
}
