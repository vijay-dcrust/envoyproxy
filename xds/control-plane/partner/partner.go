package partner

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"k8s.io/apimachinery/pkg/util/yaml"
)

var (
	ConfigPath = "/Users/vijay.pal/public_projects/envoyproxy/xds/control-plane/partner"
)

func init() {
	if os.Getenv("GRADE") == "production" {
		ConfigPath = "/var/config"
	}
}

type partner struct {
	Name        string `yaml:"name"`
	Tls_Auth    string `yaml:"tls_auth"`
	HostName    string `yaml:"hostname"`
	Destination string `yaml:"destination"`
	Dest_Port   int    `yaml:"dest_port"`
}

type Cluster struct {
	Name        string
	Destination string
	DestPort    int
}

func GetPartnerList() ([]partner, error) {
	configfile := fmt.Sprintf("%s/%s", ConfigPath, "config.yaml")

	yfile, err := ioutil.ReadFile(configfile)
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
		return v, nil
	}
	return []partner{}, errors.New("empty partner list")
}
