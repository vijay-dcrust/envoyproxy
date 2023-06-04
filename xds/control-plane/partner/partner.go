package partner

import (
	"fmt"
	"io/ioutil"
	"log"

	"k8s.io/apimachinery/pkg/util/yaml"
)

type partner struct {
	Name        string `yaml:"name"`
	Tls_Auth    string `yaml:"tls_auth"`
	HostName    string `yaml:"hostname"`
	Destination string `yaml:"destination"`
}

type Cluster struct {
	Name        string
	Destination string
	DestPort    int
}

func GetPartnerList() {
	yfile, err := ioutil.ReadFile("/Users/vijay.pal/public_projects/envoyproxy/xds/control-plane/partner/config.yaml")
	if err != nil {

		log.Fatal(err)
	}
	partnerData := make(map[string][]partner)

	err = yaml.Unmarshal(yfile, &partnerData)
	if err != nil {
		fmt.Println("error reading partner config file")
		log.Fatal(err)
	}
	for _, v := range partnerData {
		for k, l := range v {
			fmt.Printf("%d -> %s\n", k, l)

		}
	}
	//return partnerData
}
