package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
)

const (
	TIMEOUT = 5
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

	fmt.Printf("Server %s  Port %d Zone %s\n", server, port, zone)

	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

//	test1 := Test1(ip2resolver(server, port), zone)
//	test2 := Test2(ip2resolver(server, port), zone)
// test3 := Test3(ip2resolver(server, port), zone)
test4 := Test4(ip2resolver(server, port), zone)

//	PrintResult("Test1", test1)
//	PrintResult("Test2", test2)
// PrintResult("Test3", test3)
PrintResult("Test4", test4)
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
	if opt := r.IsEdns0(); opt==nil {
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
	if opt==nil {
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
  qopt.Option = append(qopt.Option, &edns100 )
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
	if opt==nil {
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
