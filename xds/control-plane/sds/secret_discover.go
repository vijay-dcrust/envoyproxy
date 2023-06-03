package sds

import (
	"io/ioutil"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/golang/protobuf/ptypes/wrappers"
	"istio.io/pkg/log"
)

// MakeSecrets generates an SDS secret
func CreateSecret() []*auth.Secret {
	secretName := "server-cert"
	log.Infof(">>>>>>>>>>>>>>>>>>> creating Secret " + secretName)
	priv, err := ioutil.ReadFile("server-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	pub, err := ioutil.ReadFile("server-cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	ca, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}

	return []*auth.Secret{
		{
			Name: secretName,
			Type: &auth.Secret_TlsCertificate{
				TlsCertificate: &auth.TlsCertificate{
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(priv)},
					},
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(pub)},
					},
				},
			},
		},
		{
			Name: "ca-key",
			Type: &auth.Secret_ValidationContext{
				ValidationContext: &auth.CertificateValidationContext{
					TrustedCa: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(ca)},
					},
				},
			},
		},
	}
}

// CreateDownStreamContext returns a tls context to be added into listener/cluster tls filters
func CreateDownStreamContext() *auth.DownstreamTlsContext {
	secretName := "server-cert"
	log.Infof(">>>>>>>>>>>>>>>>>>> creating Secret " + secretName)
	// priv, err := ioutil.ReadFile("server-key.pem")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// pub, err := ioutil.ReadFile("server-cert.pem")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// ca, err := ioutil.ReadFile("ca.crt")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	return &auth.DownstreamTlsContext{
		CommonTlsContext: &auth.CommonTlsContext{
			// TlsParams: &auth.TlsParameters{
			// 	TlsMinimumProtocolVersion: auth.TlsParameters_TLSv1_3,
			// 	CipherSuites:              []string{"ECDHE-RSA-AES128-GCM-SHA256"},
			// },
			ValidationContextType: &auth.CommonTlsContext_ValidationContext{
				ValidationContext: &auth.CertificateValidationContext{
					TrustedCa: &core.DataSource{
						//Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(ca)},
						Specifier: &core.DataSource_Filename{Filename: "/Users/vijay.pal/public_projects/envoyproxy/xds/control-plane/ca.crt"},
					},
					VerifySubjectAltName: []string{"localhost"},
				},
			},
			TlsCertificates: []*auth.TlsCertificate{
				{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_Filename{Filename: "/Users/vijay.pal/public_projects/envoyproxy/xds/control-plane/server-cert.pem"},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_Filename{Filename: "/Users/vijay.pal/public_projects/envoyproxy/xds/control-plane/server-key.pem"},
					},
				},
				// add more dynamic TLS certificates here if needed
			},
		},
		// RequireClientCertificate: &wrappers.BoolValue{
		// 	Value: true,
		// },
		RequireSni: &wrappers.BoolValue{
			Value: true,
		},
	}
}
