package event

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "time"
	"net"
)

type Event struct {
    SaddrRaw [16]byte   // union { __u32 saddr_v4; __u8 saddr_v6[16]; }
    DaddrRaw [16]byte   // union { __u32 daddr_v4; __u8 daddr_v6[16]; }
    Comm     [16]byte   // TASK_COMM_LEN
    DeltaUs  uint64
    TsUs     uint64
    Tgid     uint32
    Af       int32
    Lport    uint16
    Dport    uint16
}

func UnmarshalBinary(data []byte) (*Event, error) {
    var event Event
    reader := bytes.NewReader(data)
    if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
        return nil, err
    }
    return &event, nil
}

func (e *Event) SaddrV4() net.IP {
    return net.IPv4(e.SaddrRaw[0], e.SaddrRaw[1], e.SaddrRaw[2], e.SaddrRaw[3])
}

func (e *Event) SaddrV6() net.IP {
    return net.IP(e.SaddrRaw[:])
}

func (e *Event) DaddrV4() net.IP {
    return net.IPv4(e.DaddrRaw[0], e.DaddrRaw[1], e.DaddrRaw[2], e.DaddrRaw[3])
}

func (e *Event) DaddrV6() net.IP {
    return net.IP(e.DaddrRaw[:])
}


func PrintEventInfo(e *Event) {
    timestamp := time.Now().Format("15:04:05")
    comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
    latencyMs := float64(e.DeltaUs) / 1000.0

    var ipVer, saddr, daddr string
    if e.Af == 2 { // AF_INET
        ipVer = "v4"
        saddr = e.SaddrV4().String()
        daddr = e.DaddrV4().String()
    } else if e.Af == 10 { // AF_INET6
        ipVer = "v6"
        saddr = e.SaddrV6().String()
        daddr = e.DaddrV6().String()
    } else {
        ipVer = "??"
        saddr, daddr = "-", "-"
    }

    fmt.Printf("%-10s %-6d %-12s %-2s %-16s %-6d %-16s %-5d %.3f\n",
        timestamp, e.Tgid, comm, ipVer, saddr, e.Lport, daddr, e.Dport, latencyMs)
}