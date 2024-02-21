package config

import (
	"os"

	yaml "gopkg.in/yaml.v3"
)

var (
	Tst             chan *TaskContext
	Configuration   *Config
	ValidScrapeInfo map[string]string = map[string]string{"hostname": "1", "sysDesc": "1", "netAddr": "1"}
	RegisterUri     string = "/srv-monitor/pub/agent/register"
)

func InitTaskStatusChan() {
	Tst = make(chan *TaskContext, Configuration.Api.Max_running)
}

type Config struct {
	Api struct {
		Max_running int `yaml:"max_running"`
		Parallel    int `yaml:"parallel"`
		CacheTime   int `yaml:"result_cache_time"`
	} `yaml:"jobs"`

	Aes struct {
		Algo string `yaml:"algo,omitempty"`
		Key  string `yaml:"key"`
		Iv   string `yaml:"iv"`
	} `yaml:"aes"`

	Server struct {
		Register      bool   `yaml:"register"`
		Authorization string `yaml:"authorization"`
		Address       string `yaml:"address"`
		RegName       string `yaml:"reg-name"`
		RegFreq       int    `yaml:"reg-freq"`
	} `yaml:"server"`
}

func LoadFile(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	cfg := &Config{}
	err = yaml.Unmarshal(content, cfg)
	if err != nil {
		return err
	}
	Configuration = cfg
	err = SetEnc(cfg.Aes.Key, cfg.Aes.Iv)
	if nil != err {
		return err
	}
	return nil
}

type Other struct {
	Mode         string `default:"strict" json:"mode"`  // "valid-only"/"all", default "valid-only"
	SourceEncode string `default:"utf-8" json:"source_encode"` // the encoding of raw retrieved data, "utf-8"/"gbk", default "utf-8"
}

type SSHAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SSHTask struct {
	Ports   []uint16   `json:"ports"`
	Auths   []*SSHAuth `json:"auths"`
	Iprange []string   `json:"iprange"`
	Info    []string   `json:"scrape_info"` // "hostname"/"sysDesc"/"netAddr"
	Other   Other      `json:"other"`
}

type SSHSubTask struct {
	Ip    string
	Info  []string
	Auths []*SSHAuth
	Ports []uint16
	Other *Other
}

type SNMPAuth struct {
	Version            string  `json:"version"`  // v2c/v3
	SecurityLevel      string  `json:"security_level"`    // noAuthNoPriv authNoPriv authPriv
	Community          string  `json:"community"`
	Username           string  `json:"username"`
	Password           string  `json:"password"`
	AuthProtocol       string  `json:"auth_protocol"`  // MD5 SHA SHA256 SHA512
	PrivProtocol       string  `json:"priv_protocol"`  // AES DES
	PrivPassword       string  `json:"priv_password"`
}

type SNMPTask struct {
	Ports   []uint16    `json:"ports"`
	Auths   []*SNMPAuth `json:"auths"`
	Iprange []string   `json:"iprange"`
	Info    []string   `json:"scrape_info"` // "hostname"/"sysDesc"/"netAddr"
	Other   Other      `json:"other"`
}

type SNMPSubTask struct {
	Ip    string
	Info  []string
	Auths []*SNMPAuth
	Ports []uint16
	Other *Other
}

type ARPTask struct {
	Iprange []string   `json:"iprange"`
}

type ARPSubTask struct {
	Ip    string
}

func InvalidScrapeInfo(scraped []string) []string {
	var invalid []string = make([]string, 0)
	for _, v := range scraped {
		if ValidScrapeInfo[v] != "1" {
			invalid = append(invalid, v)
		}
	}
	return invalid
}

type Item struct {
	Ip          string   `json:"ip"`
	Hostname    string   `json:"hostname"`
	SysDesc     string   `json:"sysDesc"`
	NetAddr     []string `json:"netAddr"`
	Manufacture []string `json:"manufacture"`
}

type TaskContext struct {
	Id         string      `json:"id"`
	TaskType   string      `json:"type"`
	SubmitInfo interface{} `json:"-"`
	StartsAt   int64       `json:"startsAt"`
	EndsAt     int64       `json:"endsAt"`
	Status     string      `json:"status"`
	Message    string      `json:"message"`
	Result     []*Item     `json:"result"`
	Ondelete   int64       `json:"-"`
}
