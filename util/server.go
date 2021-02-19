package mdns

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	registry "github.com/unistack-org/micro/v3/register"
	regutil "github.com/unistack-org/micro/v3/util/register"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	mdnsGroupIPv4 = net.ParseIP("224.0.0.251")
	mdnsGroupIPv6 = net.ParseIP("ff02::fb")

	// mDNS wildcard addresses
	mdnsWildcardAddrIPv4 = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.0"),
		Port: 5353,
	}
	mdnsWildcardAddrIPv6 = &net.UDPAddr{
		IP:   net.ParseIP("ff02::"),
		Port: 5353,
	}

	// mDNS endpoint addresses
	ipv4Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv4,
		Port: 5353,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv6,
		Port: 5353,
	}
)

// Config is used to configure the mDNS server
type Config struct {
	// Zone must be provided to support responding to queries
	Zone Zone

	// Iface if provided binds the multicast listener to the given
	// interface. If not provided, the system default multicase interface
	// is used.
	Iface *net.Interface

	// Port If it is not 0, replace the port 5353 with this port number.
	Port int
}

// mDNS server is used to listen for mDNS queries and respond if we
// have a matching local record
type Server struct {
	config *Config

	ipv4conn *net.UDPConn
	ipv6conn *net.UDPConn

	shutdown     bool
	shutdownCh   chan struct{}
	shutdownLock sync.Mutex
	wg           sync.WaitGroup

	updates  chan *registry.Service
	services map[string][]*registry.Service
	records  map[string][]dnsmessage.Resource

	sync.RWMutex
}

// NewServer is used to create a new mDNS server from a config
func NewServer(config *Config) (*Server, error) {
	setCustomPort(config.Port)

	// Create the listeners
	// Create wildcard connections (because :5353 can be already taken by other apps)
	ipv4conn, _ := net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
	ipv6conn, _ := net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
	if ipv4conn == nil && ipv6conn == nil {
		return nil, fmt.Errorf("[ERR] mdns: Failed to bind to any udp port!")
	}

	if ipv4conn == nil {
		ipv4conn = &net.UDPConn{}
	}
	if ipv6conn == nil {
		ipv6conn = &net.UDPConn{}
	}

	// Join multicast groups to receive announcements
	p4 := ipv4.NewPacketConn(ipv4conn)
	p6 := ipv6.NewPacketConn(ipv6conn)
	p4.SetMulticastLoopback(true)
	p6.SetMulticastLoopback(true)

	if config.Iface != nil {
		if err := p4.JoinGroup(config.Iface, &net.UDPAddr{IP: mdnsGroupIPv4}); err != nil {
			return nil, err
		}
		if err := p6.JoinGroup(config.Iface, &net.UDPAddr{IP: mdnsGroupIPv6}); err != nil {
			return nil, err
		}
	} else {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		errCount1, errCount2 := 0, 0
		for _, iface := range ifaces {
			if err := p4.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv4}); err != nil {
				errCount1++
			}
			if err := p6.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6}); err != nil {
				errCount2++
			}
		}
		if len(ifaces) == errCount1 && len(ifaces) == errCount2 {
			return nil, fmt.Errorf("Failed to join multicast group on all interfaces!")
		}
	}

	s := &Server{
		config:     config,
		ipv4conn:   ipv4conn,
		ipv6conn:   ipv6conn,
		shutdownCh: make(chan struct{}),
		records:    make(map[string][]dnsmessage.Resource),
		services:   make(map[string][]*registry.Service),
		updates:    make(chan *registry.Service),
	}

	go s.recv(s.ipv4conn)
	go s.recv(s.ipv6conn)

	go s.update()
	//s.wg.Add(1)
	//go s.probe()

	return s, nil
}

func (s *Server) update() {
	var err error
	var buf []byte
	for svc := range s.updates {
		fmt.Printf("update %#+v\n", svc)
		if err = s.serviceToPacket(svc, buf); err != nil {
			fmt.Printf("%v\n", err)
		} else {
			if s.sendResponse(buf, mdnsWildcardAddrIPv4); err != nil {
				fmt.Printf("%v\n", err)
			}
		}
	}
}

// Shutdown is used to shutdown the listener
func (s *Server) Shutdown() error {
	s.shutdownLock.Lock()
	defer s.shutdownLock.Unlock()

	if s.shutdown {
		return nil
	}

	s.shutdown = true
	close(s.shutdownCh)
	s.unregister()

	if s.ipv4conn != nil {
		s.ipv4conn.Close()
	}
	if s.ipv6conn != nil {
		s.ipv6conn.Close()
	}

	//	s.wg.Wait()
	return nil
}

// recv is a long running routine to receive packets from an interface
func (s *Server) recv(c *net.UDPConn) {
	if c == nil {
		return
	}
	buf := make([]byte, 65536)
	for {
		s.shutdownLock.Lock()
		if s.shutdown {
			s.shutdownLock.Unlock()
			return
		}
		s.shutdownLock.Unlock()
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			continue
		}
		if err := s.parsePacket(buf[:n], from); err != nil {
			log.Printf("[ERR] mdns: Failed to handle query: %v", err)
		}
	}
}

// parsePacket is used to parse an incoming packet
func (s *Server) parsePacket(buf []byte, from net.Addr) error {
	var p dnsmessage.Parser
	hdr, err := p.Start(buf)
	if err != nil {
		return err
	}
	return s.handleQuery(hdr, p, from)
}

func (s *Server) LookupService(name string, opts ...registry.LookupOption) ([]*registry.Service, error) {

	return nil, nil
}

func (s *Server) Register(service *registry.Service, opts ...registry.RegisterOption) error {
	name := service.Name + ".micro."
	s.Lock()
	svcs, ok := s.services[name]
	if !ok {
		s.services[name] = []*registry.Service{service}
	} else {
		s.services[name] = regutil.Merge([]*registry.Service{service}, svcs)
	}
	s.Unlock()
	s.updates <- service
	return nil
}

func (s *Server) serviceToPacket(svc *registry.Service, buf []byte) error {
	var err error
	var name dnsmessage.Name

	b := dnsmessage.NewBuilder(buf, dnsmessage.Header{})
	b.EnableCompression()
	if err = b.StartAnswers(); err != nil {
		return err
	}

	if name, err = dnsmessage.NewName(svc.Name + ".micro."); err != nil {
		return err
	}

	if err = b.AResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60},
		dnsmessage.AResource{}); err != nil {
		return err
	}

	buf, err = b.Finish()

	return err
}

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(hdr dnsmessage.Header, p dnsmessage.Parser, from net.Addr) error {
	if hdr.OpCode != 0 {
		// "In both multicast query and multicast response messages, the OPCODE MUST
		// be zero on transmission (only standard queries are currently supported
		// over multicast).  Multicast DNS messages received with an OPCODE other
		// than zero MUST be silently ignored."  Note: OpcodeQuery == 0
		return fmt.Errorf("mdns: received query with non-zero Opcode %v: %v", hdr.OpCode, hdr)
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		// "In both multicast query and multicast response messages, the Response
		// Code MUST be zero on transmission.  Multicast DNS messages received with
		// non-zero Response Codes MUST be silently ignored."
		return fmt.Errorf("mdns: received query with non-zero Rcode %v: %v", hdr.RCode, hdr)
	}

	// TODO(reddaly): Handle "TC (Truncated) Bit":
	//    In query messages, if the TC bit is set, it means that additional
	//    Known-Answer records may be following shortly.  A responder SHOULD
	//    record this fact, and wait for those additional Known-Answer records,
	//    before deciding whether to respond.  If the TC bit is clear, it means
	//    that the querying host has no additional Known Answers.
	if hdr.Truncated {
		return fmt.Errorf("[ERR] mdns: support for DNS requests with high truncated bit not implemented: %v", hdr)
	}

	questions, err := p.AllQuestions()
	if err != nil {
		return err
	}

	var unicastAnswer, multicastAnswer []dnsmessage.Resource

	for _, question := range questions {
		mrecs, urecs := s.handleQuestion(question)
		fmt.Printf("%#+v %#+v\n", mrecs, urecs)
		multicastAnswer = append(multicastAnswer, mrecs...)
		unicastAnswer = append(unicastAnswer, urecs...)
	}

	rsp := func(unistact bool, buf []byte) error {
		// See section 18 of RFC 6762 for rules about DNS headers.
		// 18.1: ID (Query Identifier)
		// 0 for multicast response, query.Id for unicast response
		id := uint16(0)
		if true /*unicast*/ {
			id = hdr.ID
		}

		hdrnew := dnsmessage.Header{
			ID: id,
			// 18.2: QR (Query/Response) Bit - must be set to 1 in response.
			Response: true,
			// 18.3: OPCODE - must be zero in response (OpcodeQuery == 0)
			OpCode: 0,
			// 18.4: AA (Authoritative Answer) Bit - must be set to 1
			Authoritative: true,
			// The following fields must all be set to 0:
			// 18.5: TC (TRUNCATED) Bit
			// 18.6: RD (Recursion Desired) Bit
			// 18.7: RA (Recursion Available) Bit
			// 18.8: Z (Zero) Bit
			// 18.9: AD (Authentic Data) Bit
			// 18.10: CD (Checking Disabled) Bit
			// 18.11: RCODE (Response Code)
		}

		b := dnsmessage.NewBuilder(buf, hdrnew)
		b.EnableCompression()

		buf, err = b.Finish()

		return err
	}

	var buf1 []byte
	if err = rsp(false, buf1); err != nil {
		return err
	}
	if len(buf1) > 0 {
		if err := s.sendResponse(buf1, from); err != nil {
			return fmt.Errorf("mdns: error sending multicast response: %v", err)
		}
	}

	var buf2 []byte
	if err = rsp(true, buf2); err != nil {
		return err
	}
	if len(buf2) > 0 {
		if err := s.sendResponse(buf2, from); err != nil {
			return fmt.Errorf("mdns: error sending unicast response: %v", err)
		}
	}

	return nil
}

// handleQuestion is used to handle an incoming question
//
// The response to a question may be transmitted over multicast, unicast, or
// both.  The return values are DNS records for each transmission type.
func (s *Server) handleQuestion(q dnsmessage.Question) (multicastRecs, unicastRecs []dnsmessage.Resource) {
	records, ok := s.records[q.Name.String()]

	// Handle unicast and multicast responses.
	// TODO(reddaly): The decision about sending over unicast vs. multicast is not
	// yet fully compliant with RFC 6762.  For example, the unicast bit should be
	// ignored if the records in question are close to TTL expiration.  For now,
	// we just use the unicast bit to make the decision, as per the spec:
	//     RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	//     Section
	//
	//     In the Question Section of a Multicast DNS query, the top bit of the
	//     qclass field is used to indicate that unicast responses are preferred
	//     for this particular question.  (See Section 5.4.)
	if ok {
		if q.Class&(1<<15) != 0 {
			return nil, records
		}

		return records, nil
	}

	services, ok := s.services[q.Name.String()]
	if !ok {
		return nil, nil
	}

	fmt.Printf("%s\n", q.Name.String())
	fmt.Printf("%#+v\n", services)
	return nil, nil
}

/*
func (s *Server) probe() {
	defer s.wg.Done()

	sd, ok := s.config.Zone.(*MDNSService)
	if !ok {
		return
	}

	name := fmt.Sprintf("%s.%s.%s.", sd.Instance, trimDot(sd.Service), trimDot(sd.Domain))

	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypePTR)
	q.RecursionDesired = false

	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    defaultTTL,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(sd.Port),
		Target:   sd.HostName,
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    defaultTTL,
		},
		Txt: sd.TXT,
	}
	q.Ns = []dns.RR{srv, txt}

	randomizer := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 3; i++ {
		if err := s.SendMulticast(q); err != nil {
			log.Println("[ERR] mdns: failed to send probe:", err.Error())
		}
		time.Sleep(time.Duration(randomizer.Intn(250)) * time.Millisecond)
	}

	resp := new(dns.Msg)
	resp.MsgHdr.Response = true

	// set for query
	q.SetQuestion(name, dns.TypeANY)

	resp.Answer = append(resp.Answer, s.config.Zone.Records(q.Question[0])...)

	// reset
	q.SetQuestion(name, dns.TypePTR)

	// From RFC6762
	//    The Multicast DNS responder MUST send at least two unsolicited
	//    responses, one second apart. To provide increased robustness against
	//    packet loss, a responder MAY send up to eight unsolicited responses,
	//    provided that the interval between unsolicited responses increases by
	//    at least a factor of two with every response sent.
	timeout := 1 * time.Second
	timer := time.NewTimer(timeout)
	for i := 0; i < 3; i++ {
		if err := s.SendMulticast(resp); err != nil {
			log.Println("[ERR] mdns: failed to send announcement:", err.Error())
		}
		select {
		case <-timer.C:
			timeout *= 2
			timer.Reset(timeout)
		case <-s.shutdownCh:
			timer.Stop()
			return
		}
	}
}
*/

// multicastResponse us used to send a multicast response packet
func (s *Server) SendMulticast(msg *dns.Msg) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	if s.ipv4conn != nil {
		s.ipv4conn.WriteToUDP(buf, ipv4Addr)
	}
	if s.ipv6conn != nil {
		s.ipv6conn.WriteToUDP(buf, ipv6Addr)
	}
	return nil
}

// sendResponse is used to send a response packet
func (s *Server) sendResponse(buf []byte, from net.Addr) error {
	var err error

	// TODO(reddaly): Respect the unicast argument, and allow sending responses
	// over multicast.

	// Determine the socket to send from
	addr := from.(*net.UDPAddr)
	if addr.IP.To4() != nil {
		_, err = s.ipv4conn.WriteToUDP(buf, addr)
	} else {
		_, err = s.ipv6conn.WriteToUDP(buf, addr)
	}

	return err
}

func (s *Server) unregister() error {
	sd, ok := s.config.Zone.(*MDNSService)
	if !ok {
		return nil
	}

	atomic.StoreUint32(&sd.TTL, 0)
	name := fmt.Sprintf("%s.%s.%s.", sd.Instance, trimDot(sd.Service), trimDot(sd.Domain))

	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeANY)

	resp := new(dns.Msg)
	resp.MsgHdr.Response = true
	resp.Answer = append(resp.Answer, s.config.Zone.Records(q.Question[0])...)

	return s.SendMulticast(resp)
}

func setCustomPort(port int) {
	if port != 0 {
		if mdnsWildcardAddrIPv4.Port != port {
			mdnsWildcardAddrIPv4.Port = port
		}
		if mdnsWildcardAddrIPv6.Port != port {
			mdnsWildcardAddrIPv6.Port = port
		}
		if ipv4Addr.Port != port {
			ipv4Addr.Port = port
		}
		if ipv6Addr.Port != port {
			ipv6Addr.Port = port
		}
	}
}
