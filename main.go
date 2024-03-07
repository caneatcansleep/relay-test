package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 -cflags "-g -O2 -Wall" bpf proxy.c -- -I./headers

type Program uint8

const (
	ProgramNone Program = iota
	ProgramSockops
	ProgramSkSkb
)

var remoteAddr string
var listenAddr string = ""

type DetachFunc func()

// sudo cat  /sys/kernel/debug/tracing/trace_pipe
func main() {
	args := os.Args
	remoteAddr = args[1]
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Panicln(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		log.Panicln(err)
	}
	defer objs.Close()

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.Sockmap.FD(),
		Program: objs.SkSkbStreamVerdictProg,
		Attach:  ebpf.AttachSkSKBVerdict,
	}); err != nil {
		fmt.Println(err)
		return
	}

	defer func() {
		if err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.Sockmap.FD(),
			Program: objs.SkSkbStreamVerdictProg,
			Attach:  ebpf.AttachSkSKBStreamVerdict,
		}); err != nil {
			log.Printf("failed to detach sk_skb stream verdict program: %v", err)
		}
	}()

	// Create server
	ln, err := net.Listen("tcp", listenAddr+":8080")
	if err != nil {
		log.Panicln(err)
	}

	go func() {
		<-stopper
		log.Println("Stoping..")
		os.Exit(0)
	}()

	log.Println("Listening..")
	cishu := 1
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println("New connection", conn.RemoteAddr())
		go handleEcho(conn, &objs, cishu)
		cishu++
	}
}

// Handle
func handleEcho(conn net.Conn, objs *bpfObjects, cishu int) {

	conn2, err := net.Dial("tcp", remoteAddr+":8081")
	if err != nil {
		fmt.Printf("dial failed, err: %v\n", err)
		return
	}
	fmt.Println("Connected to test...")
	if cishu == 2 {
		go func() {
			time.Sleep(time.Second * 2)
			tcpConn := conn.(*net.TCPConn)
			connF, _ := tcpConn.File()
			connKey := getKey(conn)

			tcpConn2 := conn2.(*net.TCPConn)
			conn2F, _ := tcpConn2.File()
			conn2Key := getKey(conn2)

			if err := objs.Sockmap.Update(&connKey, uint32(conn2F.Fd()), ebpf.UpdateAny); err != nil {
				fmt.Printf("failed to update SockHashRx, err: %v\n", err)
				return
			}
			if err := objs.Sockmap.Update(&conn2Key, uint32(connF.Fd()), ebpf.UpdateAny); err != nil {
				fmt.Printf("failed to update SockHashRx, err: %v\n", err)
				return
			}
		}()
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	buf := make([]byte, 1500)

	go func() {
		defer wg.Done()

		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				return
			}
			conn2.Write(buf[:n])
			// log.Println("msg from normal1: ", string(buf[:n]))
		}

	}()

	go func() {
		defer wg.Done()
		for {
			n, err := conn2.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				return
			}
			conn.Write(buf[:n])

			// log.Println("msg from normal3: ", string(buf[:n]))
		}
	}()
	wg.Wait()
	fmt.Println("end handler:", conn.RemoteAddr().String())
}

func getKey(conn net.Conn) bpfSocketKey {
	dstIp, dstPort := Ipv4ToInt(conn.LocalAddr().String())
	srcIp, srcPort := Ipv4ToInt(conn.RemoteAddr().String())

	connKey := bpfSocketKey{
		DstIp:   dstIp,
		DstPort: dstPort,
		SrcIp:   srcIp,
		SrcPort: srcPort,
	}
	return connKey

}
func Ipv4ToInt(IPv4Addr string) (uint32, uint32) {
	hehe := strings.Split(IPv4Addr, ":")
	ip := net.ParseIP(hehe[0])
	ipv4 := ip.To4()
	port, _ := strconv.Atoi(hehe[1])
	return binary.BigEndian.Uint32(ipv4), uint32(port)
}
