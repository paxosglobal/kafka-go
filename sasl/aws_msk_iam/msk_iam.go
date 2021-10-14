package aws_msk_iam

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	sigv4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/segmentio/kafka-go/sasl"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const (
	signVersion = "2020_10_22" // this version is specified in the java version and is required to be this value
	signService = "kafka-cluster"
	signAction  = "kafka-cluster:Connect"
	signExpiry  = 5 * time.Minute

	signVersionKey   = "version"
	signHostKey      = "host"
	signUserAgentKey = "user-agent"
	signActionKey    = "action"

	queryActionKey = "Action"
)

var signingUserAgent = fmt.Sprintf("kafka-go/aws_msk_iam/%s", runtime.Version())

// Mechanism implements sasl.Mechanism for the AWS_MSK_IAM mechanism, based on the official java implementation:
// https://github.com/aws/aws-msk-iam-auth
type Mechanism struct {
	Signer *sigv4.Signer
	// The host of the kafka broker to connect to
	BrokerHost string
	// The region where the msk cluster is hosted
	AwsRegion string
	// The time the request is planned for. Defaults to time.Now() at time of authentication
	SignTime time.Time
	// The duration for which the presigned-request is active. Defaults to 15 minutes
	Expiry time.Duration
}

// NewMechanism creates a sasl.Mechanism for AWS_MSK_IAM
func NewMechanism(brokerHost, awsRegion string, creds *credentials.Credentials) *Mechanism {
	return &Mechanism{
		BrokerHost: brokerHost,
		AwsRegion:  awsRegion,
		Signer:     sigv4.NewSigner(creds),
		Expiry:     signExpiry,
	}
}

func (m *Mechanism) Name() string {
	return "AWS_MSK_IAM"
}

// Start produces the authentication values required for AWS_MSK_IAM. It produces the following json as a byte array,
// making use of the aws-sdk to produce the signed output.
//{
//	"version" : "<signVersion>",
//	"host" : "<broker address>",
//	"user-agent": "<user agent string from the client>",
//	"action": "kafka-cluster:Connect",
//	"x-amz-algorithm" : "<algorithm>",
//	"x-amz-credential" : "<clientAWSAccessKeyID>/<date in yyyyMMdd format>/<region>/kafka-cluster/aws4_request",
//	"x-amz-date" : "<timestamp in yyyyMMdd'T'HHmmss'Z' format>",
//	"x-amz-security-token" : "<clientAWSSessionToken if any>",
//	"x-amz-signedheaders" : "host",
//	"x-amz-expires" : "<expiration in seconds>",
//	"x-amz-signature" : "<AWS SigV4 signature computed by the client>"
//}
func (m *Mechanism) Start(ctx context.Context) (sess sasl.StateMachine, ir []byte, err error) {
	// the trailing slash and protocol are necessary here
	// the v4.Signer will take the host and the path from the url
	// the host  will be the broker host, and the path will be "/"
	url := fmt.Sprintf("kafka://%s/", m.BrokerHost)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}

	// Add the Action to the query, ahead of signing
	query := req.URL.Query()
	query.Add(queryActionKey, signAction)
	req.URL.RawQuery = query.Encode()

	signTime := m.SignTime
	if signTime.IsZero() {
		signTime = time.Now()
	}

	header, err := m.Signer.Presign(req, nil, signService, m.AwsRegion, m.Expiry, signTime)
	if err != nil {
		return nil, nil, err
	}
	signedMap := map[string]string{
		signVersionKey:   signVersion,
		signHostKey:      m.BrokerHost,
		signUserAgentKey: signingUserAgent,
		signActionKey:    signAction,
	}
	for key, vals := range header {
		signedMap[strings.ToLower(key)] = vals[0]
	}
	for key, vals := range req.URL.Query() {
		signedMap[strings.ToLower(key)] = vals[0]
	}

	signedJson, err := json.Marshal(signedMap)
	if err != nil {
		return nil, nil, err
	}
	return m, signedJson, nil
}

func (m *Mechanism) Next(ctx context.Context, challenge []byte) (bool, []byte, error) {
	// After the initial step, the authentication is complete
	// kafka will return error if it rejected the credentials, so we'd only
	// arrive here on success.
	return true, nil, nil
}
