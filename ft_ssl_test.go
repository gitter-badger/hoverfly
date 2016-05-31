package hoverfly_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http/httptest"
	"fmt"
	"net/http"
	"encoding/pem"
	"crypto/x509"
	"crypto/rand"
	"log"
	"crypto/rsa"
	"net"
	"math/big"
	"crypto/x509/pkix"
	"errors"
	"time"
	"crypto/tls"
	"net/http/httputil"
	"github.com/SpectoLabs/hoverfly/models"
	"net/url"
)

var _ = Describe("Using hoverfly with ssl", func() {

	BeforeEach(func() {
		requestCache.DeleteData()
	})

	Context("When doing mutual TLS via Hoverfly", func() {

		var s * httptest.Server
		var client * http.Client

		BeforeEach(func() {
			// GENERATE KEYS

			// generate a new key-pair
			rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatalf("generating random key: %v", err)
			}

			rootCertTmpl, err := CertTemplate()
			if err != nil {
				log.Fatalf("creating cert template: %v", err)
			}
			// describe what the certificate will be used for
			rootCertTmpl.IsCA = true
			rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
			rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			rootCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

			rootCert, rootCertPEM, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)

			if err != nil {
				panic(err)
			}

			// create a key-pair for the server
			servKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatalf("generating random key: %v", err)
			}

			// create a template for the server
			servCertTmpl, err := CertTemplate()
			if err != nil {
				log.Fatalf("creating cert template: %v", err)
			}
			servCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
			servCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			servCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

			// create a certificate which wraps the server's public key, sign it with the root private key
			_, servCertPEM, err := CreateCert(servCertTmpl, rootCert, &servKey.PublicKey, rootKey)
			if err != nil {
				panic(err)
			}


			// create a key-pair for the client
			clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatalf("generating random key: %v", err)
			}

			// create a template for the client
			clientCertTmpl, err := CertTemplate()
			if err != nil {
				log.Fatalf("creating cert template: %v", err)
			}
			clientCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
			clientCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

			// the root cert signs the cert by again providing its private key
			_, clientCertPEM, err := CreateCert(clientCertTmpl, rootCert, &clientKey.PublicKey, rootKey)
			if err != nil {
				log.Fatalf("error creating cert: %v", err)
			}

			// SERVER SETUP

			// provide the private key and the cert
			servKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(servKey),
			})
			servTLSCert, err := tls.X509KeyPair(servCertPEM, servKeyPEM)
			if err != nil {
				log.Fatalf("invalid key pair: %v", err)
			}

			// create a pool of trusted certs
			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM(rootCertPEM)

			// create another test server and use the certificate
			s = httptest.NewUnstartedServer(http.HandlerFunc(okayHandler))
			s.TLS = &tls.Config{
				Certificates: []tls.Certificate{servTLSCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    certPool,
			}

			// CLIENT SETUP

			// encode and load the cert and private key for the client
			clientKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
			})
			clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
			if err != nil {
				log.Fatalf("invalid key pair: %v", err)
			}

			// configure a client to use trust those certificates
			proxy, err := url.Parse(hoverflyProxyUrl)
			client = &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxy),
					TLSClientConfig: &tls.Config{
						RootCAs: certPool,
						Certificates: []tls.Certificate{clientTLSCert},
					},
				},
			}
		})

		It("Should capture the request and response", func() {
			s.StartTLS()
			resp, err := client.Get(s.URL)

			s.Close()
			if err != nil {
				log.Fatalf("could not make GET request: %v", err)
			}
			dump, err := httputil.DumpResponse(resp, true)
			if err != nil {
				log.Fatalf("could not dump response: %v", err)
			}
			fmt.Printf("%s\n", dump)

			values, err := requestCache.GetAllValues()
			Expect(err).To(BeNil())
			payload, err := models.NewPayloadFromBytes(values[0])
			Expect(err).To(BeNil())
			Expect(payload.Response.Body).To(Equal("OK"))
		})
	})
})

func okayHandler(resp http.ResponseWriter, req *http.Request) {
	resp.Write([]byte("OK"))
}

func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Yhat, Inc."}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}


func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (
	cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}
