package cds

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/golang/protobuf/ptypes/wrappers"
	"istio.io/pkg/log"
)

var (
	RootDir = "/Users/vijay.pal/public_projects/envoyproxy/xds/control-plane"
)

func init() {
	if os.Getenv("GRADE") == "production" {
		RootDir = "/var/certs"
	}
}
func createCACertificate(vendor string) error {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"SG"},
			Province:      []string{""},
			Locality:      []string{"Singapore"},
			StreetAddress: []string{"One North"},
			PostalCode:    []string{"768979"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	caCertFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "ca-cert.pem")
	caKeyFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "ca-key.pem")

	ioutil.WriteFile(caCertFileName, caPEM.Bytes(), 0644)
	err = ioutil.WriteFile(caKeyFileName, caPrivKeyPEM.Bytes(), 0644)
	if err != nil {
		return err
	}
	return nil
}

func generateCertificate(vendor string, hostname string, usage string) error {
	caCertFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "ca-cert.pem")
	caKeyFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "ca-key.pem")
	if _, err := os.Stat(caCertFileName); err == nil {
		fmt.Printf("%s CA Certificate File exists\n", vendor)
	} else {
		fmt.Printf("%s CA Certificate File does not exist\n", vendor)
		createCACertificate(vendor)
	}
	if _, err := os.Stat(caKeyFileName); err == nil {
		fmt.Printf("%s CA Key File exists\n", vendor)
	} else {
		fmt.Printf("%s CA Key File does not exist\n", vendor)
		createCACertificate(vendor)
	}

	caf, e := ioutil.ReadFile(caCertFileName)
	if e != nil {
		fmt.Println("cfload:", e.Error())
		os.Exit(1)
	}
	ckf, e := ioutil.ReadFile(caKeyFileName)
	if e != nil {
		fmt.Println("kfload:", e.Error())
		os.Exit(1)
	}
	cpb, _ := pem.Decode(caf)
	kpb, _ := pem.Decode(ckf)
	caCrt, e := x509.ParseCertificate(cpb.Bytes)
	if e != nil {
		fmt.Println("parsex509:", e.Error())
		os.Exit(1)
	}
	caPrivKey, e := x509.ParsePKCS1PrivateKey(kpb.Bytes)
	if e != nil {
		fmt.Println("parsekey:", e.Error())
		os.Exit(1)
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{vendor},
			Country:       []string{"SG"},
			Province:      []string{""},
			Locality:      []string{"One North"},
			StreetAddress: []string{"SG"},
			PostalCode:    []string{"768979"},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{hostname},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		//SubjectKeyId: []byte{1, 2, 3, 4, 6},
		// ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCrt, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	certFileName := fmt.Sprintf("%s/%s-%s-%s", RootDir, vendor, usage, "cert.pem")
	keyFileName := fmt.Sprintf("%s/%s-%s-%s", RootDir, vendor, usage, "key.pem")

	ioutil.WriteFile(certFileName, certPEM.Bytes(), 0644)
	err = ioutil.WriteFile(keyFileName, certPrivKeyPEM.Bytes(), 0644)

	return err
}
func getCertificate(vendor string, hostname string, tls_auth string) (serverCertFile string, serverKeyFile string) {
	certFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "server-cert.pem")
	keyFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "server-key.pem")
	if _, err := os.Stat(certFileName); err == nil {
		fmt.Printf("%s Certificate File exists\n", vendor)
	} else {
		fmt.Printf("%s Certificate File does not exist\n", vendor)
		generateCertificate(vendor, hostname, "server")
		if tls_auth == "mtls" {
			generateCertificate(vendor, hostname, "client")

		}
	}
	if _, err := os.Stat(keyFileName); err == nil {
		fmt.Printf("%s Key File exists\n", vendor)
	} else {
		fmt.Printf("%s does not exist\n", vendor)
		generateCertificate(vendor, hostname, "server")
		if tls_auth == "mtls" {
			generateCertificate(vendor, hostname, "client")

		}
	}
	return certFileName, keyFileName
}

// CreateDownStreamContext returns a tls context to be added into listener/cluster tls filters
func CreateDownStreamContext(tls_auth string, vendor string, hostName string) *auth.DownstreamTlsContext {
	log.Infof(">>>>>>>>>>>>>>>>>>> Fetching Certificate for" + vendor)
	serverCertFile, serverKeyFile := getCertificate(vendor, hostName, tls_auth)
	caCertFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "ca-cert.pem")

	downStreamContext := &auth.DownstreamTlsContext{
		CommonTlsContext: &auth.CommonTlsContext{
			// TlsParams: &auth.TlsParameters{
			// 	TlsMinimumProtocolVersion: auth.TlsParameters_TLSv1_3,
			// 	CipherSuites:              []string{"ECDHE-RSA-AES128-GCM-SHA256"},
			// },
			ValidationContextType: &auth.CommonTlsContext_ValidationContext{
				ValidationContext: &auth.CertificateValidationContext{
					TrustedCa: &core.DataSource{
						//Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(ca)},
						Specifier: &core.DataSource_Filename{Filename: caCertFileName},
					},
					VerifySubjectAltName: []string{hostName},
				},
			},
			TlsCertificates: []*auth.TlsCertificate{
				{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_Filename{Filename: serverCertFile},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_Filename{Filename: serverKeyFile},
					},
				},
				// add more dynamic TLS certificates here if needed
			},
		},
		// RequireClientCertificate: &wrappers.BoolValue{
		// 	Value: true,
		// },
		// RequireSni: &wrappers.BoolValue{
		// 	Value: true,
		// },
	}
	if tls_auth == "mtls" {
		downStreamContext.RequireClientCertificate = &wrappers.BoolValue{
			Value: true,
		}
	}
	return downStreamContext
}
