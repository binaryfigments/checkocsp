package checkocsp

import (
	"bytes"
	"crypto"
	_ "crypto/sha256" // useg for crypto
	"crypto/tls"
	"crypto/x509"
	"encoding/base64" // used in requesting OCSP response
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/idna"
)

var ocspUnauthorised = []byte{0x30, 0x03, 0x0a, 0x01, 0x06}
var ocspMalformed = []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
var hasPort = regexp.MustCompile(`:\d+$`)

// Run function for starting the check
func Run(server string) (*Message, error) {
	msg := new(Message)
	msg.Question.JobTime = time.Now()
	msg.Question.JobServer = server
	controls := []*Controls{}

	var (
		err          error
		cert         *x509.Certificate
		ocspResponse *ocsp.Response
	)

	var ocspUnauthorised = []byte{0x30, 0x03, 0x0a, 0x01, 0x06}
	var ocspMalformed = []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
	var hasPort = regexp.MustCompile(`:\d+$`)

	// Valid server name (ASCII or IDN)
	server, err = idna.ToASCII(server)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Non ASCII or IDN characters in domain."
		return msg, err
	}

	var issuerFile, ocspServer string

	if !hasPort.MatchString(server) {
		server += ":443"
	}

	fmt.Println("fetching certificate from", server)

	conn, err := tls.Dial("tcp", server, nil)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Error connecting to server:" + server
		// msg.Question.JobError = err
		return msg, err
	}

	connState := conn.ConnectionState()
	peerChain := connState.PeerCertificates
	if len(peerChain) == 0 {
		err = errors.New("invalid certificate presented")
		if err != nil {
			msg.Question.JobStatus = "Failed"
			msg.Question.JobMessage = "Error, invalid certificate presented"
			return msg, err
		}
	}

	cert = peerChain[0]

	res := conn.OCSPResponse()
	if res != nil {
		fmt.Println("OCSP stapled response")
		msg.Answer.OCSPstapled = "Yes"
		ocspResponse, err = ocsp.ParseResponse(res, nil)
		if err != nil {
			msg.Question.JobStatus = "Failed"
			msg.Question.JobMessage = "Error: Can not get stapling response"
			return msg, err
		}
		msg.Answer.OCSPResponse = showOCSPResponse(ocspResponse, nil)
		conn.Close()
		msg.Question.JobStatus = "OK"
		msg.Question.JobMessage = "Job done!"
		return msg, err
	}
	conn.Close()

	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		if ocspServer == "" {
			msg.Question.JobStatus = "Failed"
			msg.Question.JobMessage = "Error: No OCSP URLs found in cert, and none given from the app."
			return msg, err
		}
		ocspURLs = []string{ocspServer}
	}

	var issuer *x509.Certificate
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchRemote(issuingCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			continue
		}
		break
	}

	if issuer == nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Error: No issuing certificate could be found."
		return msg, err
	}

	opts := ocsp.RequestOptions{
		Hash: crypto.SHA1,
	}

	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &opts)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Error in ocspRequest"
		return msg, err
	}

	for _, ocspserver := range ocspURLs {
		fmt.Println("sending OCSP request to", ocspserver)
		msg.Answer.OCSPstapled = "No"
		msg.Answer.OCSPServer = ocspserver

		var resp *http.Response
		if len(ocspRequest) > 256 {
			buf := bytes.NewBuffer(ocspRequest)
			resp, err = http.Post(ocspserver, "application/ocsp-request", buf)
		} else {
			reqURL := ocspserver + "/" + base64.StdEncoding.EncodeToString(ocspRequest)
			resp, err = http.Get(reqURL)
		}

		if err != nil {
			// fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			msg.Answer.OCSPResponseMessage = "Unknown error OCSP lookup."
			continue
		}

		if resp.StatusCode != http.StatusOK {
			// fmt.Fprintln(os.Stderr, "[!] invalid OCSP response from server", ocspserver)
			msg.Answer.OCSPResponseMessage = "invalid OCSP response from server" + ocspserver
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// fmt.Fprintf(os.Stderr, "[!] failed to read response body: %s\n", err)
			msg.Answer.OCSPResponseMessage = "Failed to read response body."
			continue
		}
		resp.Body.Close()

		if bytes.Equal(body, ocspUnauthorised) {
			// fmt.Fprintf(os.Stderr, "[!] OCSP request unauthorised\n")
			msg.Answer.OCSPResponseMessage = "OCSP request unauthorised."
			continue
		}

		if bytes.Equal(body, ocspMalformed) {
			// fmt.Fprintf(os.Stderr, "[!] OCSP server did not understand the request\n")
			msg.Answer.OCSPResponseMessage = "OCSP server did not understand the request."
			continue
		}

		ocspResponse, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			msg.Answer.OCSPResponseMessage = "Invalid OCSP response from server."
			// fmt.Fprintf(os.Stderr, "[!] invalid OCSP response from server\n")
			// fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			// fmt.Fprintf(os.Stderr, "[!] Response is %x\n", body)
			ioutil.WriteFile("/tmp/ocsp.bin", body, 0644)
			continue
		}

		fmt.Println("OCSP response from", ocspserver)
		msg.Answer.OCSPResponse = showOCSPResponse(ocspResponse, issuer)

		if issuerFile != "" && ocspResponse.Certificate != nil {
			p := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: ocspResponse.Certificate.Raw,
			}
			err = ioutil.WriteFile(issuerFile, pem.EncodeToMemory(p), 0644)
			if err != nil {
				msg.Question.JobStatus = "Failed"
				msg.Question.JobMessage = "Wrote issuing certificate to: " + issuerFile
				return msg, err
			}
			fmt.Println("Wrote issuing certificate to", issuerFile)
		}
	}
	// Add Controls to struct
	msg.Controls = controls

	msg.Question.JobStatus = "OK"
	msg.Question.JobMessage = "Job done!"

	return msg, err
}

func showOCSPResponse(res *ocsp.Response, issuer *x509.Certificate) *OCSPResponse {
	OcspResp := new(OCSPResponse)
	fmt.Printf("\tCertificate status: ")
	switch res.Status {
	case ocsp.Good:
		fmt.Println("good")
		OcspResp.CertificateStatus = "Good"
	case ocsp.Revoked:
		fmt.Println("revoked")
		OcspResp.CertificateStatus = "Revoked"
	case ocsp.ServerFailed:
		fmt.Println("server failed")
		OcspResp.CertificateStatus = "Server Failed"
	case ocsp.Unknown:
		fmt.Println("unknown")
		OcspResp.CertificateStatus = "Unknown"
	default:
		fmt.Println("unknown response received from server")
		OcspResp.CertificateStatus = "Unknown response received from server"
	}

	// fmt.Printf("\tCertificate serial number: %s\n", res.SerialNumber)
	OcspResp.CertificateSerial = res.SerialNumber
	// fmt.Printf("\tStatus produced at %s\n", res.ProducedAt)
	OcspResp.TimeStatusProduced = res.ProducedAt
	// fmt.Printf("\tCurrent update: %s\n", res.ThisUpdate)
	OcspResp.TimeCurrentUpdate = res.ThisUpdate
	// fmt.Printf("\tNext update: %s\n", res.NextUpdate)
	OcspResp.TimeNextUpdate = res.NextUpdate

	if res.Status == ocsp.Revoked {
		fmt.Printf("\tCertificate revoked at %s\n", res.RevokedAt)
	}

	if issuer != nil && res.Certificate == nil {
		fmt.Printf("\tSignature status: ")
		if err := res.CheckSignatureFrom(issuer); err == nil {
			fmt.Println("OK")
			OcspResp.SignatureStatus = "OK"
		} else {
			fmt.Printf("bad signature on response (%v)\n", err)
			fmt.Println("\t(maybe wrong OCSP issuer cert?)")
			OcspResp.SignatureStatus = "Bad signature on response (maybe wrong OCSP issuer cert?)"
		}
	}
	return OcspResp
}

func parseCert(in []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(in)
	if p != nil {
		if p.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate")
		}
		in = p.Bytes
	}

	return x509.ParseCertificate(in)
}

func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	in, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return parseCert(in)
}
