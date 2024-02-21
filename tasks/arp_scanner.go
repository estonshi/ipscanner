package tasks

import (
	config "agents/ipscanner/config"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	cmap "github.com/orcaman/concurrent-map"
)

type Info struct {
	Mac      net.HardwareAddr // IP地址
	Hostname string           // 主机名
	Manuf    string           // 厂商信息
}

type Sniffer struct {
	ipNet      *net.IPNet       // ipNet 存放 IP地址和子网掩码
	localHaddr net.HardwareAddr // 本机的mac地址，发以太网包需要用到
	iface      string           // 网络接口名

	sentPk     cmap.ConcurrentMap         // 发送的包IP
	sendingFinished bool        // 已完成发送
}

func invalidARPTaskInfo(arpTask config.ARPTask) bool {
	if len(arpTask.Iprange) != 2 || !config.IsValidIp(arpTask.Iprange[0]) || !config.IsValidIp(arpTask.Iprange[1]) {
		return true
	}
	if config.CompareIp(arpTask.Iprange[0], arpTask.Iprange[1]) > 0 {
		return true
	}
	return false
}

func startARPScanner(task *config.TaskContext) {
	defer func() {
		error := recover()
		if error != nil {
			log.Errorf("[ARP-SCANNER] Panic: %v", error)
			finishT(task, nil, fmt.Errorf("panic: %v", error))
		}
	}()
	// init
	initT(task)
	// create channel
	var taskChan chan *config.ARPSubTask = make(chan *config.ARPSubTask, config.Configuration.Api.Parallel*10)
	var restChan chan *config.Item = make(chan *config.Item, config.Configuration.Api.Parallel)
	// run
	for i := 0; i < config.Configuration.Api.Parallel; i++ {
		go startARPCollect(taskChan, restChan)
	}
	result, err := startScanARP(task, taskChan, restChan)
	// end
	finishT(task, result, err)
}

func startScanARP(task *config.TaskContext, taskChan chan<- *config.ARPSubTask, restChan chan *config.Item) ([]*config.Item, error) {
	result := make([]*config.Item, 0, 10)
	tinfo, ok := task.SubmitInfo.(*config.ARPTask)
	if !ok {
		return nil, errors.New("type assertion failed: config.ARPTask")
	}
	log.Infof("[ARP-SCANNER] (%s) Start ARP scanning, ip range: %s", task.Id, tinfo.Iprange)
	startTime := time.Now().Unix()
	ipStart, err := config.NewIpv4(tinfo.Iprange[0])
	ipEnd, err2 := config.NewIpv4(tinfo.Iprange[1])
	if err != nil || err2 != nil {
		return nil, fmt.Errorf("invalid ip")
	}
	ip := ipStart.IpStr
	for {
		subTask := new(config.ARPSubTask)
		subTask.Ip = ip
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
	log.Infof("[ARP-SCANNER] (%v) ARP scanning task finished, cost %v seconds", task.Id, endTime-startTime)
	return result, nil
}

func startARPCollect(taskChan <-chan *config.ARPSubTask, restChan chan<- *config.Item) {
	var sniffer Sniffer = Sniffer{} 
	err := sniffer.setupNetInfo("")
	if err != nil {
		return
	}
	log.Debugf("sniffer: %v", sniffer)
	// listen arp packets
	go sniffer.listenARP(restChan)
	// send arp packets
	for task := range taskChan {
		ip := task.Ip
		log.Infof("[ARPScanner] (%v) start detecting", ip)
		go sniffer.sendArpPackage(ip)
	}
	sniffer.sendingFinished = true
}

func (snf *Sniffer) setupNetInfo(f string) (error) {
	var ifs []net.Interface
	var err error
	if f == "" {
		ifs, err = net.Interfaces()
	} else {
		// 已经选择iface
		var it *net.Interface
		it, err = net.InterfaceByName(f)
		if err == nil {
			ifs = append(ifs, *it)
		}
	}
	if err != nil {
		log.Errorf("[ARPScanner] Failed to fetch local net interface: ", err)
		return err
	}
	for _, it := range ifs {
		addr, _ := it.Addrs()
		for _, a := range addr {
			if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					snf.ipNet = ip
					snf.localHaddr = it.HardwareAddr
					snf.iface = it.Name
					snf.sentPk = cmap.New()
					snf.sendingFinished = false
					goto END
				}
			}
		}
	}
END:
	if snf.ipNet == nil || len(snf.localHaddr) == 0 {
		log.Errorf("[ARPScanner] Failed to fetch local net interface")
		return err
	}
	return nil
}

func (snf *Sniffer) sendArpPackage(ip string) (error) {
	srcIp := net.ParseIP(snf.ipNet.IP.String()).To4()
	dstIp := net.ParseIP(ip).To4()
	if srcIp == nil || dstIp == nil {
		log.Error("[ARPScanner] ip parse failure")
		return fmt.Errorf("ip parse failure: srcIp=%s, dstIp=%s", snf.ipNet.IP.String(), ip)
	}
	// EthernetType 0x0806  ARP
	ether := &layers.Ethernet{
		SrcMAC:       snf.localHaddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         layers.ARPRequest,
		SourceHwAddress:   snf.localHaddr,
		SourceProtAddress: srcIp,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstIp,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(snf.iface, 2048, false, 3*time.Second)
	if err != nil {
		log.Errorf("[ARPScanner] pcap open failure: %v", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Errorf("[ARPScanner] ARP sent failure: %v", err)
		return err
	}
	snf.sentPk.Set(ip, "1")
	log.Debugf("send arp packet to %s, total sent: %d", ip, len(snf.sentPk))
	return nil
}

func (snf *Sniffer) listenARP(restChan chan<- *config.Item) (error) {
	handle, err := pcap.OpenLive(snf.iface, 2048, false, pcap.BlockForever)
	if err != nil {
		log.Errorf("[ARPScanner] pcap open failure: %v", err)
		return err
	}
	defer handle.Close()
	handle.SetBPFFilter("arp")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	// 结束定时器
	timer := time.NewTimer(5 * time.Second)
	timer2 := time.NewTimer(1 * time.Hour)
	defer timer.Stop()
	defer timer2.Stop()

	for {
		select {
		case p := <-ps.Packets():
			arp := p.Layer(layers.LayerTypeARP).(*layers.ARP)
			if arp != nil && arp.Operation == layers.ARPReply {
				mac := net.HardwareAddr(arp.SourceHwAddress)
				ip := net.IP(arp.SourceProtAddress).String()
				if !snf.sentPk.Has(ip) {
					continue
				} else {
					snf.sentPk.Remove(ip)
				}
				var item *config.Item = new(config.Item)
				item.Ip = ip
				item.NetAddr = []string{mac.String()}
				item.Manufacture = config.SearchManuf([]string{mac.String()})
				restChan <- item
				log.Debugf("receive arp packet: %v, waiting packets: %d", item, len(snf.sentPk))
			}
			if snf.sendingFinished && len(snf.sentPk) == 0 {
				log.Debugf("stop listening")
				restChan<- nil
				return nil
			}
		case <- timer.C:
			log.Debugf("timer triggerred")
			if !snf.sendingFinished {
				timer.Reset(5 * time.Second)
			} else {
				timer2.Reset(time.Duration(10) * time.Second)
			}
		case <- timer2.C:
			log.Debugf("stop listening (forced)")
			restChan<- nil
			return nil
		}
	}

}