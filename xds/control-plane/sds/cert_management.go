package sds

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

const (
	RootDir = "/Users/vijay.pal/public_projects/envoyproxy/xds/control-plane"
)

var (
	CaCertFile = fmt.Sprintf("%s/%s", RootDir, "ca.crt")
	CaKeyFile  = fmt.Sprintf("%s/%s", RootDir, "ca.key")
)

func generateCertificate(vendor string, hostname string) error {
	caf, e := ioutil.ReadFile(CaCertFile)
	if e != nil {
		fmt.Println("cfload:", e.Error())
		os.Exit(1)
	}
	ckf, e := ioutil.ReadFile(CaKeyFile)
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
	certFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "server-cert.pem")
	keyFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "server-key.pem")

	ioutil.WriteFile(certFileName, certPEM.Bytes(), 0644)
	err = ioutil.WriteFile(keyFileName, certPrivKeyPEM.Bytes(), 0644)

	return err
}
func getCertificate(vendor string, hostname string) (serverCertFile string, serverKeyFile string) {
	certFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "server-cert.pem")
	keyFileName := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "server-key.pem")
	if _, err := os.Stat(certFileName); err == nil {
		fmt.Printf("%s Certificate File exists\n", vendor)
	} else {
		fmt.Printf("%s Certificate File does not exist\n", vendor)
		generateCertificate(vendor, hostname)
	}
	if _, err := os.Stat(keyFileName); err == nil {
		fmt.Printf("%s Key File exists\n", vendor)
	} else {
		fmt.Printf("%s does not exist\n", vendor)
		generateCertificate(vendor, hostname)
	}

	return certFileName, keyFileName
}

// CreateDownStreamContext returns a tls context to be added into listener/cluster tls filters
func CreateDownStreamContext(tls_auth string, vendor string, hostName string) *auth.DownstreamTlsContext {
	log.Infof(">>>>>>>>>>>>>>>>>>> Fetching Certificate for" + vendor)
	serverCertFile, serverKeyFile := getCertificate(vendor, hostName)
	//interMediateCAcert := fmt.Sprintf("%s/%s-%s", RootDir, vendor, "interca-cert.pem")

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
						Specifier: &core.DataSource_Filename{Filename: CaCertFile},
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
