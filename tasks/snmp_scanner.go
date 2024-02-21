package tasks

import (
	config "agents/ipscanner/config"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	log "github.com/sirupsen/logrus"
)

func invalidSNMPTaskInfo(snmpTask config.SNMPTask) bool {
	if len(snmpTask.Auths) == 0 {
		return true
	}
	if len(snmpTask.Iprange) != 2 || !config.IsValidIp(snmpTask.Iprange[0]) || !config.IsValidIp(snmpTask.Iprange[1]) {
		return true
	}
	if config.CompareIp(snmpTask.Iprange[0], snmpTask.Iprange[1]) > 0 {
		return true
	}
	if len(snmpTask.Ports) == 0 {
		return true
	}
	// check auth info
	for _, auth := range snmpTask.Auths {
		switch auth.Version {
		case "v1":
			fallthrough
		case "v2c":
			if auth.Community == "" {
				return true
			}
		case "v3":
			{
				switch auth.SecurityLevel {
				case "noAuthNoPriv":
					continue
				case "authPriv":
					if auth.PrivPassword == "" {
						return true
					}
					if privProtocol(auth.PrivProtocol) == gosnmp.NoPriv {
						return true
					}
					fallthrough
				case "authNoPriv":
					if auth.Username == "" || auth.Password == "" {
						return true
					}
					if authProtocol(auth.AuthProtocol) == gosnmp.NoAuth {
						return true
					}
				default:
					return true
				}
			}
		default:
			return true
		}
	}
	return false
}

func authProtocol(str string) (gosnmp.SnmpV3AuthProtocol) {
	switch str {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA256":
		return gosnmp.SHA256
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func privProtocol(str string) (gosnmp.SnmpV3PrivProtocol) {
	switch str {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES256":
		return gosnmp.AES256
	case "AES256C":
		return gosnmp.AES256C
	default:
		return gosnmp.NoPriv
	}
}

func version(str string) (gosnmp.SnmpVersion) {
	switch str {
	case "v1":
		return gosnmp.Version1
	case "v2c":
		return gosnmp.Version2c
	case "v3":
		return gosnmp.Version3
	default:
		return gosnmp.Version2c
	}
}

func securityLevel(str string) (gosnmp.SnmpV3MsgFlags) {
	switch str {
	case "noAuthNoPriv":
		return gosnmp.NoAuthNoPriv
	case "authNoPriv":
		return gosnmp.AuthNoPriv
	case "authPriv":
		return gosnmp.AuthPriv
	default:
		return gosnmp.AuthPriv
	}
}

func snmpClient(auth *config.SNMPAuth, ip string, port uint16) (*gosnmp.GoSNMP, error) {
	snmp := &gosnmp.GoSNMP{
		Target:        ip,
		Port:          port,
		Community:     auth.Community,
		Version:       version(auth.Version),
		Timeout:       time.Duration(5) * time.Second,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      securityLevel(auth.SecurityLevel),
		SecurityParameters: &gosnmp.UsmSecurityParameters {
			UserName: auth.Username,
			AuthenticationProtocol: authProtocol(auth.AuthProtocol),
			AuthenticationPassphrase: auth.Password,
			PrivacyProtocol: privProtocol(auth.PrivProtocol),
			PrivacyPassphrase: auth.PrivPassword,
		},
	}
	err := snmp.Connect()
	if nil == err {
		// check authentication
		_, err2 := snmp.Get([]string{"1.3.6.1.2.1.1.1.0"})
		if nil != err2 {
			err = err2
		}
	}
	return snmp, err
}

func startSNMPScanner(task *config.TaskContext) {
	defer func() {
		error := recover()
		if error != nil {
			log.Errorf("[SNMP-SCANNER] Panic: %v", error)
			finishT(task, nil, fmt.Errorf("panic: %v", error))
		}
	}()
	// init
	initT(task)
	// create channel
	var taskChan chan *config.SNMPSubTask = make(chan *config.SNMPSubTask, config.Configuration.Api.Parallel*10)
	var restChan chan *config.Item = make(chan *config.Item, config.Configuration.Api.Parallel)
	// run
	for i := 0; i < config.Configuration.Api.Parallel; i++ {
		go startSNMPCollect(taskChan, restChan)
	}
	result, err := startScanSNMP(task, taskChan, restChan)
	// end
	finishT(task, result, err)
}

func startSNMPCollect(taskChan <-chan *config.SNMPSubTask, restChan chan<- *config.Item) {
	for task := range taskChan {
		ip := task.Ip
		log.Infof("[SNMPScanner] (%v) start detecting", ip)
		if !pingIpAddr(ip) {
			log.Warnf("[SNMPScanner] (%v) Ping failed", ip)
			continue
		}
		var item *config.Item = new(config.Item)
		item.Ip = ip
		var succ bool = false
		for _, port := range task.Ports {
			for _, auth := range task.Auths {
				client, err := snmpClient(auth, ip, port)
				if err != nil {
					log.Warnf("[SNMPScanner] (%v) SNMP connection failed", ip)
					continue
				}
				for _, property := range task.Info {
					switch property {
					case "hostname":
						{
							hostname, err := snmpGet([]string{"1.3.6.1.2.1.1.5.0"}, client, task.Other.SourceEncode)
							if nil == err {
								item.Hostname = hostname
							}
						}
					case "sysDesc":
						{
							sys, err := snmpGet([]string{"1.3.6.1.2.1.1.1.0"}, client, task.Other.SourceEncode)
							if nil == err {
								item.SysDesc = sys
							}
						}
					case "netAddr":
						{
							var netAddr []string
							var raw map[string]string
							rawDesc, err2 := snmpWalk("1.3.6.1.2.1.2.2.1.2", client, task.Other.SourceEncode)
							raw, err3 := snmpWalk("1.3.6.1.2.1.2.2.1.6", client, "hex")
							if nil == err2 && nil == err3 {
								netAddr = filterMac(rawDesc, raw)
							}
							item.NetAddr = netAddr
							item.Manufacture = config.SearchManuf(item.NetAddr)
						}
					}
				}
				restChan <- item
				client.Conn.Close()
				succ = true
				break
			}
			if succ {
				break
			}
		}
		if !succ && task.Other.Mode == "all" {
			restChan <- item
		}
	}
	// send complete message
	restChan <- nil
}

func startScanSNMP(task *config.TaskContext, taskChan chan<- *config.SNMPSubTask, restChan chan *config.Item) ([]*config.Item, error) {
	result := make([]*config.Item, 0, 10)
	tinfo, ok := task.SubmitInfo.(*config.SNMPTask)
	if !ok {
		return nil, errors.New("type assertion failed: config.SNMPTask")
	}
	log.Infof("[SNMP-SCANNER] (%s) Start SNMP scanning, ip range: %s", task.Id, tinfo.Iprange)
	startTime := time.Now().Unix()
	ipStart, err := config.NewIpv4(tinfo.Iprange[0])
	ipEnd, err2 := config.NewIpv4(tinfo.Iprange[1])
	if err != nil || err2 != nil {
		return nil, fmt.Errorf("invalid ip")
	}
	ip := ipStart.IpStr
	for {
		subTask := new(config.SNMPSubTask)
		subTask.Auths = tinfo.Auths
		subTask.Info = tinfo.Info
		subTask.Ip = ip
		subTask.Ports = tinfo.Ports
		subTask.Other = &tinfo.Other
		taskChan <- subTask
		if ip == ipEnd.IpStr {
			close(taskChan)
			break
		}
		ip, err = ipStart.Next()
		if nil != err {
			break
		}
	}
	// 等待返回结果
	var i int = 0
	for item := range restChan {
		if nil == item {
			i++
			if i == config.Configuration.Api.Parallel {
				close(restChan)
				continue
			} else {
				continue
			}
		}
		result = append(result, item)
		updateT(task, result)
	}
	endTime := time.Now().Unix()
	log.Infof("[SNMP-SCANNER] (%v) SNMP scanning task finished, cost %v seconds", task.Id, endTime-startTime)
	return result, nil
}

// func judgeOSSnmp(client *gosnmp.GoSNMP, encode string) (string, string, error) {
// 	var sys string
// 	oids := []string{"1.3.6.1.2.1.1.1.0"}	
// 	sys, err := snmpGet(oids, client, encode)
// 	if err != nil {
// 		return "", "", err
// 	}
// 	if strings.Contains(sys, "Linux") || strings.Contains(sys, "linux") {
// 		return "linux", sys, nil
// 	} else if strings.Contains(sys, "Windows") || strings.Contains(sys, "windows") {
// 		return "windows", sys, nil
// 	} else {
// 		return "","", errors.New("unknown os")
// 	}
// }

// return value
func snmpGet(oids []string, client *gosnmp.GoSNMP, encode string) (string, error) {
	result, err := client.Get(oids)
	if err != nil {
		return "", err
	}
	out := result.Variables[0].Value.([]byte)
	// byte transfer
	if encode != "" && encode != "utf-8" {
		out, err = config.ToUtf8(out, encode)
		if err != nil {
			return "", err
		}
	}
	return strings.Trim(string(out),"\n"), nil
}

// return map{oid: value}
func snmpWalk(oid string, client *gosnmp.GoSNMP, encode string) (map[string]string, error) {
	result := make(map[string]string)
	fn := func(v gosnmp.SnmpPDU) error {
		var out string
		if len(v.Value.([]byte)) == 0 {
			return nil
		}
		if encode == "hex" {
			out = hex.EncodeToString(v.Value.([]byte))
		} else {
			switch v.Type {
			case gosnmp.OctetString, gosnmp.BitString:
				out = strings.Trim(strings.Trim(tryTransformEncode(v.Value.([]byte), encode), "\n"), " ")
			default:
				out = fmt.Sprintf("%d", gosnmp.ToBigInt(v.Value)) 
			}
		}
		if out == "" {
			return nil
		}
		result[v.Name] = out
		return nil
	}

	err := client.Walk(oid, fn)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func tryTransformEncode(src []byte, encode string) string {
	if encode != "" && encode != "utf-8" {
		out, err := config.ToUtf8(src, encode)
		if err != nil {
			return string(src)
		} else {
			return string(out)
		}
	} else {
		return string(src)
	}
}

func filterMac(rawDesc map[string]string, raw map[string]string) []string {
	invalidIfIndex := map[string]string{}
	result := []string{}
	for oid, value := range rawDesc {
		if strings.HasPrefix(value, "ve") || strings.HasPrefix(value, "docker") || 
				strings.HasPrefix(value, "br") || strings.HasPrefix(value, "lo") {
			tmp := strings.Split(oid, ".")
			invalidIfIndex[tmp[len(tmp)-1]] = "1"
		}
	}
	for oid, value := range raw {
		tmp := strings.Split(oid, ".")
		if _,ok := invalidIfIndex[tmp[len(tmp)-1]]; !ok {
			if len(value) == 12 {
				result = append(result, value[0:2]+":"+value[2:4]+":"+value[4:6]+":"+value[6:8]+":"+value[8:10]+":"+value[10:12])
			} else {
				result = append(result, value)
			}
		}
	}
	return result
}
