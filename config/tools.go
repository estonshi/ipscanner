package config

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net"
	"regexp"
	"strings"

	manuf "agents/ipscanner/manuf"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

//GBK -> UTF-8
func GbkToUtf8(s []byte) ([]byte, error) {
    reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
    all, err := ioutil.ReadAll(reader)
    if err != nil {
        return all, err
    }
    return all, nil
}

//GB18030 -> UTF-8
func Gb18030ToUtf8(s []byte) ([]byte, error) {
    reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GB18030.NewDecoder())
    all, err := ioutil.ReadAll(reader)
    if err != nil {
        return all, err
    }
    return all, nil
}

func ToUtf8(s []byte, encode string) ([]byte, error) {
	switch encode {
	case "gbk":
		return GbkToUtf8(s)
	case "gb18030":
		return Gb18030ToUtf8(s)
	}
	return nil, errors.New("unknown encode")
}

func GetSelfIp() (string) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
 
	for i := 0; i < len(netInterfaces); i++ {
		if (netInterfaces[i].Flags & net.FlagUp) != 0 {
			addrs, _ := netInterfaces[i].Addrs()
 
			for _, address := range addrs {
				if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						return ipnet.IP.String()
					}
				}
			}
		}
	}
	return ""
}

func ParseMacAddr(raw string) []string {
	reg, err := regexp.Compile("([0-9a-fA-F]{2}(:|-)){5}[0-9a-fA-F]{2}")
	if err != nil {
		return nil
	}
	addr := reg.FindAllString(raw, -1)
	for i,tmp := range addr {
		news := strings.ReplaceAll(tmp, "-", ":")
		addr[i] = news
	}
	return addr
}

func SearchManuf(mac []string) []string {
	ma := map[string]string{}
	for _, ms := range mac {
		manufacture := manuf.Search(ms)
		if manufacture != "" {
			ma[manufacture] = "1"
		}
	}
	keys := make([]string, 0, len(ma))
	for k := range ma {
		keys = append(keys, k)
	}
	return keys
}