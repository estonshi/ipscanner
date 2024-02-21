package config

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var (
	ipRegex string = "^((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}$"
)

type Ipv4 struct{
	lock  sync.Mutex
	IpStr string
	IpArr [4]int
}

func IsValidIp(ip string) (bool) {
	matched, err := regexp.MatchString(ipRegex, ip)
	if err != nil {
		return false
	}
	return matched
}

// IP1 小于 IP2 返回值 <0 ；IP1 大于 IP2 返回值 >0 ；IP1 等于 IP2 返回值 =0
func CompareIp(ip1 string, ip2 string) (int64) {
	var ip1q int64 = 0
	var ip2q int64 = 0
	for i, seg := range strings.Split(ip1, ".") {
		v, _ := strconv.Atoi(seg)
		ip1q += int64(math.Pow(100,float64(3-i)))*255 + int64(v)
	}
	for i, seg := range strings.Split(ip2, ".") {
		v, _ := strconv.Atoi(seg)
		ip2q += int64(math.Pow(100,float64(3-i)))*255 + int64(v)
	}
	return ip1q - ip2q
}

func NewIpv4 (ipStr string) (*Ipv4, error) {
	if !IsValidIp(ipStr) {
		return nil, fmt.Errorf("invalid ip string: %v", ipStr)
	}
	var ip = new(Ipv4)
	ip.IpStr = ipStr
	for i, seg := range strings.Split(ipStr, ".") {
		v, err := strconv.Atoi(seg)
		if nil != err {
			return nil, err
		}
		ip.IpArr[i] = v
	}
	return ip, nil
}

func (ip *Ipv4) Next() (string, error) {
	ip.lock.Lock()
	err := ip.iterNext(3)
	ipStr := ip.get()
	ip.lock.Unlock()
	return ipStr, err
}

func (ip *Ipv4) iterNext(loc int) (error) {
	if ip.IpArr[loc] < 255 {
		ip.IpArr[loc]++
		return nil
	} else {
		ip.IpArr[loc] = 0
		if loc > 0 {
			return ip.iterNext(loc-1)
		} else {
			return errors.New("no more ip")
		}
	}
}

func (ip *Ipv4) Previous() (string, error) {
	ip.lock.Lock()
	err := ip.iterPrev(3)
	ipStr := ip.get()
	ip.lock.Unlock()
	return ipStr, err
}

func (ip *Ipv4) iterPrev(loc int) (error) {
	if ip.IpArr[loc] > 0 {
		ip.IpArr[loc]--
		return nil
	} else {
		ip.IpArr[loc] = 255
		if loc > 0 {
			return ip.iterPrev(loc-1)
		} else {
			return errors.New("no more ip")
		}
	}
}

func (ip *Ipv4) get() (string) {
	ipStr := fmt.Sprintf("%v.%v.%v.%v", ip.IpArr[0], ip.IpArr[1], ip.IpArr[2], ip.IpArr[3])
	ip.IpStr = ipStr
	return ip.IpStr
}