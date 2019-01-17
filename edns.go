package main

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/miekg/dns"
)

const (
	TIMEOUT   = 5
	EDNS0SIZE = 4096
)

var verbose bool = false
var port uint = 53

func main() {

	// define and parse command line arguments
	flag.BoolVar(&verbose, "verbose", false, "print more information while running")
	flag.BoolVar(&verbose, "v", false, "print more information while running")
	flag.UintVar(&port, "p", 53, "Port to connect to (default 53)")
	flag.Parse()

	if flag.NArg() != 2 {
		fmt.Printf("Usage: %s [-v] <server> <zone>\n", os.Args[0])
		os.Exit(1)
	}

	server := flag.Arg(0)
	zone := flag.Arg(1)

	fmt.Printf("Server %s   Port %d   Zone %s\n", server, port, zone)

	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	test1 := Test1(ip2resolver(server, port), zone)
	test2 := Test2(ip2resolver(server, port), zone)
	test3 := Test3(ip2resolver(server, port), zone)
	test4 := Test4(ip2resolver(server, port), zone)
	test5 := Test5(ip2resolver(server, port), zone)
	test6 := Test6(ip2resolver(server, port), zone)
	test7 := Test7(ip2resolver(server, port), zone)
	test8 := Test8(ip2resolver(server, port), zone)
	test9 := Test9(ip2resolver(server, port), zone)
	//	test10 := Test10(ip2resolver(server, port), zone)

	PrintResult("Test1", test1)
	PrintResult("Test2", test2)
	PrintResult("Test3", test3)
	PrintResult("Test4", test4)
	PrintResult("Test5", test5)
	PrintResult("Test6", test6)
	PrintResult("Test7", test7)
	PrintResult("Test8", test8)
	PrintResult("Test9", test9)
	//	PrintResult("Test10", test10)
}

func PrintResult(name string, err error) {
	if err != nil {
		fmt.Printf("%s failure! %s\n", name, err)
	} else {
		fmt.Printf("%s success\n", name)
	}
}

func ip2resolver(server string, port uint) string {
	if strings.ContainsAny(":", server) {
		// IPv6 address
		server = "[" + server + "]"
	}
	server = fmt.Sprintf("%s:%d", server, port)
	return server
}

// Test1
//
// dig +norec +noedns soa zone @server
// expect: SOA
// expect: NOERROR
func Test1(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.RecursionDesired = false
	query.AuthenticatedData = true
	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("Test1: no answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Test1: rcode %s", dns.RcodeToString[r.Rcode]))
	}

	foundSOA := false
	for _, answer := range r.Answer {
		if answer.Header().Rrtype != dns.TypeSOA {
			return errors.New("Test2: unexpected answer")
		}
		foundSOA = true
	}
	if !foundSOA {
		return errors.New("Test2: no SOA in answer")
	}

	return nil
}

// Test2
//
// Plain EDNS
// dig +norec +edns=0 soa zone @server
// expect: SOA
// expect: NOERROR
// expect: OPT record with version set to 0
// See RFC6891
func Test2(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.SetEdns0(EDNS0SIZE, false)
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("Test2: no answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Test2: rcode %s", dns.RcodeToString[r.Rcode]))
	}

	foundSOA := false
	for _, answer := range r.Answer {
		if answer.Header().Rrtype != dns.TypeSOA {
			return errors.New("Test2: unexpected answer")
		}
		foundSOA = true
	}
	if !foundSOA {
		return errors.New("Test2: no SOA in answer")
	}
	if opt := r.IsEdns0(); opt == nil {
		return errors.New("Test2: No OPT received")
	} else {
		if opt.Version() != 0 {
			return errors.New(fmt.Sprintf("Test2: EDNS0 Version %d received", opt.Version()))
		}
	}

	// success
	return nil
}

// Test3
//
// EDNS - Unknown Version
//
// dig +norec +edns=100 +noednsneg soa zone @server
// expect: BADVERS
// expect: OPT record with version set to 0
// expect: not to see SOA
// See RFC6891, 6.1.3. OPT Record TTL Field Use
func Test3(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.SetEdns0(EDNS0SIZE, false)
	query.IsEdns0().SetVersion(100)
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("Test3: no answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Test3: rcode %s", dns.RcodeToString[r.Rcode]))
	}

	for _ = range r.Answer {
		return errors.New("Test3: unexpected answer")
	}

	opt := r.IsEdns0()
	if opt == nil {
		return errors.New("Test3: No OPT received")
	} else {
		if opt.Version() != 0 {
			return errors.New(fmt.Sprintf("Test3: EDNS0 Version %d received", opt.Version()))
		}
	}
	if opt.ExtendedRcode() != dns.RcodeBadVers {
		return errors.New(fmt.Sprintf("Test3: extended rcode %s", dns.RcodeToString[r.Rcode]))
	}

	// success
	return nil
}

type EDNS0_100 struct {
	dns.EDNS0_NSID
}

func (e *EDNS0_100) Option() uint16 { return 100 }

// Test4
//
// EDNS - Unknown Option
//
// dig +norec +ednsopt=100 soa zone @server [1]
// expect: SOA
// expect: NOERROR
// expect: OPT record with version set to 0
// expect: that the option will not be present in response
// See RFC6891, 6.1.2 Wire Format
func Test4(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.SetEdns0(EDNS0SIZE, false)
	qopt := query.IsEdns0()
	qopt.SetVersion(0)
	edns100 := EDNS0_100{}
	edns100.Code = 100
	edns100.Nsid = ""
	qopt.Option = append(qopt.Option, &edns100)
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("No answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Rcode %d %s", r.Rcode, dns.RcodeToString[r.Rcode]))
	}

	foundSOA := false
	for _, answer := range r.Answer {
		if answer.Header().Rrtype != dns.TypeSOA {
			return errors.New("unexpected answer")
		}
		foundSOA = true
	}
	if !foundSOA {
		return errors.New("no SOA in answer")
	}

	opt := r.IsEdns0()
	if opt == nil {
		return errors.New("No OPT received")
	} else {
		if opt.Version() != 0 {
			return errors.New(fmt.Sprintf("EDNS0 Version %d received", opt.Version()))
		}
	}
	if opt.ExtendedRcode() != 15 {
		return errors.New(fmt.Sprintf("extended rcode %d %s", opt.ExtendedRcode(), dns.RcodeToString[opt.ExtendedRcode()]))
	}
	if len(opt.Option) > 0 {
		return errors.New("option data received")
	}

	// success
	return nil
}

// EDNS - Unknown Flag
//
// dig +norec +ednsflags=0x80 soa zone @server [1]
// expect: SOA
// expect: NOERROR
// expect: OPT record with version set to 0
// expect: Z bits to be clear in response
// See RFC6891, 6.1.4 Flags
func Test5(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.SetEdns0(EDNS0SIZE, false)
	qopt := query.IsEdns0()
	qopt.SetVersion(0)
	qhead := qopt.Header()
	qhead.Ttl |= 0x0064
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("No answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Rcode %d %s", r.Rcode, dns.RcodeToString[r.Rcode]))
	}

	foundSOA := false
	for _, answer := range r.Answer {
		if answer.Header().Rrtype != dns.TypeSOA {
			return errors.New("unexpected answer")
		}
		foundSOA = true
	}
	if !foundSOA {
		return errors.New("no SOA in answer")
	}

	opt := r.IsEdns0()
	if opt == nil {
		return errors.New("No OPT received")
	}
	if opt.Version() != 0 {
		return errors.New(fmt.Sprintf("EDNS0 Version %d received", opt.Version()))
	}
	if opt.ExtendedRcode() != 15 {
		return errors.New(fmt.Sprintf("extended rcode %d %s", opt.ExtendedRcode(), dns.RcodeToString[opt.ExtendedRcode()]))
	}
	if len(opt.Option) > 0 {
		return errors.New("option data received")
	}
	if opt.Header().Ttl != 0x0000 {
		return errors.New(fmt.Sprintf("Z bits not clear in response 0x%04x", opt.Header().Ttl))
	}
	// success
	return nil
}

// EDNS - DO=1 (DNSSEC)
//
// dig +norec +dnssec soa zone @server
// expect: NOERROR
// expect: SOA
// expect: OPT record with version set to 0
// expect: DO flag in response if RRSIG is present in response
// See RFC3225
func Test6(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.SetEdns0(EDNS0SIZE, false)
	query.IsEdns0().SetDo()
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("No answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Rcode %d %s", r.Rcode, dns.RcodeToString[r.Rcode]))
	}

	foundSOA := false
	foundRRSIG := false
	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeSOA {
			foundSOA = true
			continue
		}
		if answer.Header().Rrtype == dns.TypeRRSIG {
			foundRRSIG = true
			continue
		}
		return errors.New("unexpected answer")
	}
	if !foundSOA {
		return errors.New("no SOA in answer")
	}

	opt := r.IsEdns0()
	if opt == nil {
		return errors.New("No OPT received")
	}
	if opt.Version() != 0 {
		return errors.New(fmt.Sprintf("EDNS0 Version %d received", opt.Version()))
	}
	if opt.ExtendedRcode() != 15 {
		return errors.New(fmt.Sprintf("extended rcode %d %s", opt.ExtendedRcode(), dns.RcodeToString[opt.ExtendedRcode()]))
	}
	if len(opt.Option) > 0 {
		return errors.New("option data received")
	}
	if foundRRSIG && !opt.Do() {
		return errors.New("RRSIG received but DO not set")
	}
	if !foundRRSIG && opt.Do() {
		return errors.New("No RRSIG received but DO set")
	}
	// success
	return nil
}

// EDNS - Truncated Response
//
// dig +norec +dnssec +bufsize=512 +ignore dnskey zone @server
// expect: NOERROR
// expect: OPT record with version set to 0
// See RFC6891, 7. Transport Considerations
func Test7(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeDNSKEY)
	query.SetEdns0(512, false)
	query.IsEdns0().SetDo()
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	// ignore truncated error, the message has been decaded anyway
	if err != nil && err.Error() != "dns: failed to unpack truncated message" {
		return err
	}
	if r == nil {
		return errors.New("No answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Rcode %d %s", r.Rcode, dns.RcodeToString[r.Rcode]))
	}

	opt := r.IsEdns0()
	if opt == nil {
		return errors.New("No OPT received")
	}
	if opt.Version() != 0 {
		return errors.New(fmt.Sprintf("EDNS0 Version %d received", opt.Version()))
	}
	if opt.ExtendedRcode() != 15 {
		return errors.New(fmt.Sprintf("extended rcode %d %s", opt.ExtendedRcode(), dns.RcodeToString[opt.ExtendedRcode()]))
	}
	// success
	return nil
}

// EDNS - Unknown Version with Unknown Option
//
// expect: BADVERS
// dig +norec +edns=100 +noednsneg +ednsopt=100 soa zone @server
// expect: OPT record with version set to 0
// expect: not to see SOA
// expect: that the option will not be present in response
// See RFC6891
func Test8(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.SetEdns0(EDNS0SIZE, false)
	query.IsEdns0().SetVersion(100)
	qopt := query.IsEdns0()
	qopt.SetVersion(100)
	edns100 := EDNS0_100{}
	edns100.Code = 100
	edns100.Nsid = ""
	qopt.Option = append(qopt.Option, &edns100)
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	// ignore truncated error, the message has been decaded anyway
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("No answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Rcode %d %s", r.Rcode, dns.RcodeToString[r.Rcode]))
	}

	for _ = range r.Answer {
		return errors.New("Unexpected answer")
	}

	opt := r.IsEdns0()
	if opt == nil {
		return errors.New("No OPT received")
	}
	if opt.Version() != 0 {
		return errors.New(fmt.Sprintf("EDNS0 Version %d received", opt.Version()))
	}
	if opt.ExtendedRcode() != dns.RcodeBadVers {
		return errors.New(fmt.Sprintf("Extended rcode %s", dns.RcodeToString[r.Rcode]))
	}
	if len(opt.Option) > 0 {
		return errors.New("option data received")
	}

	// success
	return nil
}

// Test9
//
// DNS COOKIES
//
// See RFC7873
//
func Test9(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.SetEdns0(EDNS0SIZE, false)
	cookie := new(dns.EDNS0_COOKIE)
	cookie.Code = dns.EDNS0COOKIE
	clientCookie := fmt.Sprintf("%16x", rand.Int63())
	cookie.Cookie = clientCookie
	qopt := query.IsEdns0()
	qopt.Option = append(qopt.Option, cookie)
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	// ignore truncated error, the message has been decaded anyway
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("No answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Rcode %d %s", r.Rcode, dns.RcodeToString[r.Rcode]))
	}

	for _ = range r.Answer {
		//		return errors.New("Unexpected answer")
	}

	opt := r.IsEdns0()
	if opt == nil {
		return errors.New("No OPT received")
	}
	if opt.Version() != 0 {
		return errors.New(fmt.Sprintf("EDNS0 Version %d received", opt.Version()))
	}
	if opt.ExtendedRcode() != 15 {
		return errors.New(fmt.Sprintf("Extended rcode %s", dns.RcodeToString[r.Rcode]))
	}
	if len(opt.Option) == 0 {
		return errors.New("Cookies not supported")
	}
	foundCookie := false
	//var ropt dns.EDNS0
	for _, ropt := range opt.Option {
		if ropt.Option() == dns.EDNS0COOKIE {
			if !strings.HasPrefix(ropt.(*dns.EDNS0_COOKIE).Cookie, clientCookie) {
				return errors.New(fmt.Sprintf("Client cookie did not match clientCookie 0x%8s Received cookie %s", clientCookie, ropt.(*dns.EDNS0_COOKIE).Cookie))
			}
			foundCookie = true
		}
	}
	if !foundCookie {
		return errors.New("DNS Cookies not supported")
	}

	// success
	return nil
}

// Test10
//
// Nsid
//
// RFC
//
func Test10(server, zone string) error {
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeSOA)
	query.SetEdns0(EDNS0SIZE, false)
	cookie := new(dns.EDNS0_COOKIE)
	cookie.Code = dns.EDNS0COOKIE
	clientCookie := fmt.Sprintf("%0x", rand.Int31())
	fmt.Println("COOKIE", clientCookie)
	cookie.Cookie = clientCookie
	qopt := query.IsEdns0()
	qopt.Option = append(qopt.Option, cookie)
	query.RecursionDesired = false
	query.AuthenticatedData = true

	// Setting up resolver
	client := new(dns.Client)
	client.ReadTimeout = TIMEOUT * 1e9

	// make the query and wait for answer
	r, _, err := client.Exchange(query, server)

	// check for errors
	// ignore truncated error, the message has been decaded anyway
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("No answer")
	}
	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Rcode %d %s", r.Rcode, dns.RcodeToString[r.Rcode]))
	}

	for _ = range r.Answer {
		//		return errors.New("Unexpected answer")
	}

	opt := r.IsEdns0()
	if opt == nil {
		return errors.New("No OPT received")
	}
	if opt.Version() != 0 {
		return errors.New(fmt.Sprintf("EDNS0 Version %d received", opt.Version()))
	}
	if opt.ExtendedRcode() != 15 {
		return errors.New(fmt.Sprintf("Extended rcode %s", dns.RcodeToString[r.Rcode]))
	}
	if len(opt.Option) == 0 {
		return errors.New("Cookies not supported")
	}
	foundCookie := false
	//var ropt dns.EDNS0
	for _, ropt := range opt.Option {
		if ropt.Option() == dns.EDNS0COOKIE {
			if !strings.HasPrefix(ropt.(*dns.EDNS0_COOKIE).Cookie, clientCookie) {
				return errors.New(fmt.Sprintf("Client cookie did not match clientCookie 0x%8s Received cookie %s", clientCookie, ropt.(*dns.EDNS0_COOKIE).Cookie))
			}
			foundCookie = true
		}
	}
	if !foundCookie {
		return errors.New("DNS Cookies not supported")
	}

	// success
	return nil
}
