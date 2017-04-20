package checkocsp

import (
	"math/big"
	"time"

	"gopkg.in/mgo.v2/bson"
)

/*
 * Used Models
 */

// Message struct for returning the question and the answer.
type Message struct {
	ID       bson.ObjectId `json:"id" bson:"_id,omitempty"`
	Question Question      `json:"question"`
	Answer   Answer        `json:"answer"`
	Controls []*Controls   `json:"controls,omitempty"`
}

// Question struct for retuning what information is asked.
type Question struct {
	JobServer  string    `json:"server"`
	JobStatus  string    `json:"status"`
	JobMessage string    `json:"message"`
	JobTime    time.Time `json:"time"`
}

// Answer struct the answer of the question.
type Answer struct {
	OCSPServer          string        `json:"ocspserver,omitempty"`
	OCSPstapled         string        `json:"ocsp_stapled,omitempty"`
	OCSPResponse        *OCSPResponse `json:"ocsp_response,omitempty"`
	OCSPResponseMessage string        `json:"ocsp_response_message,omitempty"`
}

// OCSPResponse struct
type OCSPResponse struct {
	CertificateStatus           string    `json:"certificate_status"`
	CertificateSerial           *big.Int  `json:"certificate_cerial"`
	TimeStatusProduced          time.Time `json:"time_status_produced"`
	TimeCurrentUpdate           time.Time `json:"time_current_update"`
	TimeNextUpdate              time.Time `json:"time_next_update"`
	SignatureStatus             string    `json:"signature_status"`
	CertificateRevokedAt        time.Time `json:"certificate_revoked_at"`
	CertificateRevocationReason int       `json:"certificate_revocation_reason"`
}

// Controls struct check information
type Controls struct {
	Shortcode   string `json:"shortcode,omitempty"`
	Group       string `json:"group,omitempty"`
	Description string `json:"description,omitempty"`
	Points      int    `json:"points,omitempty"`
}
