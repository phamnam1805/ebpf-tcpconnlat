package probe

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"ebpf-tcpconnlat/internal/event"
)

//go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/tcpconnlat.bpf.c -- -O2


const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2

type probe struct {
	bpfObjects 	*probeObjects
	tcpV4ConnectLink link.Link
	tcpV6ConnectLink link.Link
	tcpRcvStateProcessLink link.Link

}

func setRlimit() error {
     log.Println("Setting rlimit")

     return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
         Cur: twentyMegaBytes,
         Max: fortyMegaBytes,
     })
}

func setUnlimitedRlimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Failed setting infinite rlimit: %v", err)
		return err
	}
	return nil
}

func (p *probe) loadObjects(minLatency int, pid int)  error {
	log.Printf("Loading probe object into kernel")

	objs := probeObjects{}

	spec, err := loadProbe()
	if err != nil {
		return err
	}

	if minLatency > 0 {
		if err := spec.Variables["targ_min_us"].Set(uint64(minLatency)); err != nil {
			log.Printf("Failed setting targ_min_us: %v", err)
			return err
		}

		log.Printf("Set targ_min_us to %d us", minLatency)
	}

	if pid > 0 {
		if err := spec.Variables["targ_tgid"].Set(uint32(pid)); err != nil {
			log.Printf("Failed setting targ_tgid: %v", err)
			return err
		}

		log.Printf("Set targ_tgid to %d", pid)
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return err
	}

	p.bpfObjects = &objs

	return nil
}


func (p *probe) attachPrograms() error {
	log.Printf("Attaching bpf programs to kernel")

	tcpV4ConnectLink, err := link.AttachTracing(link.TracingOptions{
        Program: p.bpfObjects.FentryTcpV4Connect,
    })
    if err != nil {
        log.Printf("Failed to link fentry/tcp_v4_connect: %v", err)
        return err
    }
    p.tcpV4ConnectLink = tcpV4ConnectLink
	log.Printf("Successfully linked fentry/tcp_v4_connect")

	tcpV6ConnectLink, err := link.AttachTracing(link.TracingOptions{
        Program: p.bpfObjects.FentryTcpV6Connect,
    })
    if err != nil {
        log.Printf("Failed to link fentry/tcp_v6_connect: %v", err)
        return err
    }
    p.tcpV6ConnectLink = tcpV6ConnectLink
	log.Printf("Successfully linked fentry/tcp_v6_connect")

	tcpRcvStateProcessLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.bpfObjects.FentryTcpRcvStateProcess,
	})
	if err != nil {
		log.Printf("Failed to link fentry/tcp_rcv_state_process: %v", err)
		return err
	}
	p.tcpRcvStateProcessLink = tcpRcvStateProcessLink
	log.Printf("Successfully linked fentry/tcp_rcv_state_process")

	return nil
}

func newProbe(minLatency int, pid int) (*probe, error) {
	log.Println("Creating a new probe")


	prbe := probe{
	}

	if err := prbe.loadObjects(minLatency, pid); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.attachPrograms(); err != nil {
		log.Printf("Failed attaching bpf programs: %v", err)
		return nil, err
	}

	return &prbe, nil
}

func (p *probe) Close() error {
	log.Println("Closing eBPF object")

	if p.tcpV4ConnectLink != nil {
        p.tcpV4ConnectLink.Close()
    }

	if p.tcpV6ConnectLink != nil {
        p.tcpV6ConnectLink.Close()
    }

	if p.tcpRcvStateProcessLink != nil {
		p.tcpRcvStateProcessLink.Close()
	}

	return nil
}


func Run(ctx context.Context, minLatency int, pid int) error {
	log.Println("Starting up the probe")

	if err := setRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return err
	}

	probe, err := newProbe(minLatency, pid)
	if err != nil {
		log.Printf("Failed creating new probe: %v", err)
		return err
	}
	
	eventPipe := probe.bpfObjects.probeMaps.Events
	eventReader, err := perf.NewReader(eventPipe, os.Getpagesize())
	if err != nil {
		log.Fatalf("opening perf reader: %s", err)
	}
	defer eventReader.Close()

	fmt.Printf("%-10s %-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n", "TIME", "PID", "COMM",
               "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)")

	go func() {
        for {
			if ctx.Err() != nil {
				return
			}
            record, err := eventReader.Read()
            if err != nil {
                if ctx.Err() != nil {
                    return
                }
                log.Printf("Failed reading from ringbuf: %v", err)
                continue
            }
            eventAttrs, err := event.UnmarshalBinary(record.RawSample)
            if err != nil {
                log.Printf("Could not unmarshal event: %+v", record.RawSample)
                continue
            }
            event.PrintEventInfo(eventAttrs)
        }
    }()

	<-ctx.Done()
    log.Println("Context cancelled, shutting down...")
    return probe.Close()
}