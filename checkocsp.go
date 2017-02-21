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
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/idna"
)

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
		ocspServer   string
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

	ip, err := net.ResolveIPAddr("ip", server)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Error resolving an IP address for: " + server
		return msg, err
	}
	fmt.Println("IP of server is:", ip)

	if !hasPort.MatchString(server) {
		server += ":443"
	}

	dialconf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", server, dialconf)
	if err != nil {
		msg.Question.JobStatus = "Failed"
		msg.Question.JobMessage = "Error connecting to server:" + server
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
			msg.Answer.OCSPResponseMessage = "Unknown error OCSP lookup."
			continue
		}

		if resp.StatusCode != http.StatusOK {
			msg.Answer.OCSPResponseMessage = "Invalid OCSP response from server" + ocspserver
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			msg.Answer.OCSPResponseMessage = "Failed to read response body."
			continue
		}
		resp.Body.Close()

		if bytes.Equal(body, ocspUnauthorised) {
			msg.Answer.OCSPResponseMessage = "OCSP request unauthorised."
			continue
		}

		if bytes.Equal(body, ocspMalformed) {
			msg.Answer.OCSPResponseMessage = "OCSP server did not understand the request."
			continue
		}

		ocspResponse, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			msg.Answer.OCSPResponseMessage = "Invalid OCSP response from server."
			ioutil.WriteFile("/tmp/ocsp.bin", body, 0644)
			continue
		}

		msg.Answer.OCSPResponse = showOCSPResponse(ocspResponse, issuer)
	}
	// Add Controls to struct
	msg.Controls = controls

	msg.Question.JobStatus = "OK"
	msg.Question.JobMessage = "Job done!"

	return msg, err
}

func showOCSPResponse(res *ocsp.Response, issuer *x509.Certificate) *OCSPResponse {
	OcspResp := new(OCSPResponse)
	switch res.Status {
	case ocsp.Good:
		OcspResp.CertificateStatus = "Good"
	case ocsp.Revoked:
		OcspResp.CertificateStatus = "Revoked"
	case ocsp.ServerFailed:
		OcspResp.CertificateStatus = "Server Failed"
	case ocsp.Unknown:
		OcspResp.CertificateStatus = "Unknown"
	default:
		OcspResp.CertificateStatus = "Unknown response received from server"
	}

	OcspResp.CertificateSerial = res.SerialNumber
	OcspResp.TimeStatusProduced = res.ProducedAt
	OcspResp.TimeCurrentUpdate = res.ThisUpdate
	OcspResp.TimeNextUpdate = res.NextUpdate

	if res.Status == ocsp.Revoked {
		OcspResp.CertificateRevokedAt = res.RevokedAt
		OcspResp.CertificateRevocationReason = res.RevocationReason

		/*
			TODO: For later
			unspecified (0)
			keyCompromise (1)
			CACompromise (2)
			affiliationChanged (3)
			superseded (4)
			cessationOfOperation (5)
			certificateHold (6)
			removeFromCRL (8)
			privilegeWithdrawn (9)
			AACompromise (10)
		*/
	}

	if issuer != nil && res.Certificate == nil {
		if err := res.CheckSignatureFrom(issuer); err == nil {
			OcspResp.SignatureStatus = "OK"
		} else {
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
