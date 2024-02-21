package tasks

import (
	config "agents/ipscanner/config"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ping/ping"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func startSSHScanner(task *config.TaskContext) {
	defer func() {
		error := recover()
		if error != nil {
			log.Errorf("[SSH-SCANNER] Panic: %v", error)
			finishT(task, nil, fmt.Errorf("panic: %v", error))
		}
	}()
	// init
	initT(task)
	// create channel
	var taskChan chan *config.SSHSubTask = make(chan *config.SSHSubTask, config.Configuration.Api.Parallel*10)
	var restChan chan *config.Item = make(chan *config.Item, config.Configuration.Api.Parallel)
	// run
	for i := 0; i < config.Configuration.Api.Parallel; i++ {
		go startSSHCollect(taskChan, restChan)
	}
	result, err := startScanSSH(task, taskChan, restChan)
	// end
	finishT(task, result, err)
}

func invalidSSHTaskInfo(sshTask config.SSHTask) bool {
	if len(sshTask.Auths) == 0 {
		return true
	}
	if len(sshTask.Iprange) != 2 || !config.IsValidIp(sshTask.Iprange[0]) || !config.IsValidIp(sshTask.Iprange[1]) {
		return true
	}
	if config.CompareIp(sshTask.Iprange[0], sshTask.Iprange[1]) > 0 {
		return true
	}
	if len(sshTask.Ports) == 0 {
		return true
	}
	return false
}

func startScanSSH(task *config.TaskContext, taskChan chan<- *config.SSHSubTask, restChan chan *config.Item) ([]*config.Item, error) {
	result := make([]*config.Item, 0, 10)
	tinfo, ok := task.SubmitInfo.(*config.SSHTask)
	if !ok {
		return nil, errors.New("type assertion failed: config.SSHTask")
	}
	log.Infof("[SSH-SCANNER] (%s) Start SSH scanning, ip range: %s", task.Id, tinfo.Iprange)
	startTime := time.Now().Unix()
	ipStart, err := config.NewIpv4(tinfo.Iprange[0])
	ipEnd, err2 := config.NewIpv4(tinfo.Iprange[1])
	if err != nil || err2 != nil {
		return nil, fmt.Errorf("invalid ip")
	}
	ip := ipStart.IpStr
	for {
		subTask := new(config.SSHSubTask)
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
	log.Infof("[SSH-SCANNER] (%v) SSH scanning task finished, cost %v seconds", task.Id, endTime-startTime)
	return result, nil
}

func startSSHCollect(taskChan <-chan *config.SSHSubTask, restChan chan<- *config.Item) {
	for task := range taskChan {
		ip := task.Ip
		log.Infof("[SSHScanner] (%v) start detecting", ip)
		if !pingIpAddr(ip) {
			log.Warnf("[SSHScanner] (%v) Ping failed", ip)
			continue
		}
		var item *config.Item = new(config.Item)
		item.Ip = ip
		var succ bool = false
		for _, port := range task.Ports {
			for _, auth := range task.Auths {
				client, err := sshClient(auth.Username, auth.Password, ip, port)
				if err != nil {
					log.Warnf("[SSHScanner] (%v) SSH connection failed", ip)
					continue
				}
				// judge os
				os, sys, err := judgeOSSsh(client, task.Other.SourceEncode)
				if nil != err {
					log.Warnf("[SSHScanner] (%v) Unknown operating system", ip)
					continue
				}
				for _, property := range task.Info {
					switch property {
					case "hostname":
						{
							hostname, err := sshExecute("hostname", client, task.Other.SourceEncode)
							if nil == err {
								item.Hostname = hostname
							}
						}
					case "sysDesc":
						{
							item.SysDesc = sys
						}
					case "netAddr":
						{
							var raw string
							if os == "windows" {
								raw, err = sshExecute("getmac /FO CSV /NH", client, task.Other.SourceEncode)
							} else {
								raw, err = sshExecute("cat /sys/class/net/e*/address", client, task.Other.SourceEncode)
							}
							if nil == err {
								item.NetAddr = config.ParseMacAddr(raw)
								item.Manufacture = config.SearchManuf(item.NetAddr)
							}
						}
					}
				}
				restChan <- item
				client.Close()
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

func pingIpAddr(ip string) bool {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return false
	}
	pinger.Count = 3
	pinger.Timeout = time.Second * 1
	pinger.SetPrivileged(true)
	pinger.Run()
	return pinger.Statistics().PacketsRecv > 0
}

func sshClient(user, password, host string, port uint16) (*ssh.Client, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	hostKeyCallbk := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}

	clientConfig = &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		Timeout:         3 * time.Second,
		HostKeyCallback: hostKeyCallbk,
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}
	return client, nil
}

func sshExecute(cmd string, client *ssh.Client, encode string) (string, error) {
	var (
		session *ssh.Session
		err     error
	)
	if session, err = client.NewSession(); err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.Output(cmd)
	if err != nil {
		return "", err
	}

	// byte transfer
	if encode != "" && encode != "utf-8" {
		out, err = config.ToUtf8(out, encode)
		if err != nil {
			return "", err
		}
	}

	return strings.Trim(strings.Trim(string(out), "\r\n"), "\n"), nil
}

func judgeOSSsh(client *ssh.Client, encode string) (string, string, error) {
	var sys string
	sys, err := sshExecute("uname --kernel-release --kernel-name", client, encode)
	if nil != err {
		sys, err := sshExecute("ver", client, encode)
		if nil != err {
			return "", "", errors.New("unknown os")
		} else {
			return "windows", sys, nil
		}
	} else {
		return "linux", sys, nil
	}
}
