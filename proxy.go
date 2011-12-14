package convergence

import (
	"bufio"
	"io"

	"log"
	"net"
	"regexp"
)

func copy(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	// setup one-way forwarding of stream traffic
	io.Copy(a, b)
	// and close both connections when a read fails
	a.Close()
	b.Close()
}

func forward(local net.Conn, remoteAddr string) {
	raddr, err := net.ResolveTCPAddr("", remoteAddr)
	if err != nil {
		local.Write([]byte("HTTP/1.0 502 That's no street, Pete\r\n\r\n"))
		local.Close()
		return
	}
	if raddr.Port != 4242 { // only accept connections to port 4242 
		local.Write([]byte("HTTP/1.0 502 Connection to invalid port\r\n\r\n"))
		local.Close()
		return
	}
	remote, err := net.DialTCP("net", nil, raddr)
	if err != nil {
		local.Write([]byte("HTTP/1.0 502 It's dead, Fred\r\n\r\n"))
		local.Close()
		return
	}
	remote.SetKeepAlive(true)
	local.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))
	go copy(local, remote)
	go copy(remote, local)
}

func newconn(c net.Conn) {
	// find out the desired destination on a new connect
	connre := regexp.MustCompile("CONNECT (.*) HTTP/")
	r := bufio.NewReader(c)
	l, isprefix, err := r.ReadLine()
	if err != nil || isprefix == true {
		c.Close()
		return
	}
	m := connre.FindStringSubmatch(string(l))
	log.Println(m[1])
	if m == nil {
		c.Write([]byte("HTTP/1.0 502 Bad Gateway\r\n\r\n"))
		c.Close()
		return
	}
	// wait until we get a blank line (end of HTTP headers)
	for {
		l, _, _ := r.ReadLine()
		if l == nil {
			return
		}
		if len(l) == 0 {
			break
		}
	}
	if l != nil {
		forward(c, m[1])
	}
}
/*
Listen for connect requests on address, only forward connections to same port
*/
func ProxyListenAndServe(laddr string) error {
	netlisten, err := net.Listen("tcp", laddr)
	if netlisten == nil {
		return err
	}
	defer netlisten.Close()

	for {
		// wait for clients
		conn, err := netlisten.Accept()
		if conn != nil {
			go newconn(conn)
		} else {
			return err
		}
	}
	return nil
}
