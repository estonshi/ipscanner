package tasks

import (
	config "agents/ipscanner/config"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func StartRegistration(port string) {
	timer := time.NewTimer(10 * time.Second)
	var lastRegTs int64 
Loop:
	for {
		timer.Reset(30 * time.Second)
		select {
		case <- timer.C:
			if lastRegTs > 0 && int64(time.Now().UnixMilli())-lastRegTs <= int64(config.Configuration.Server.RegFreq)*60*1000 {
				continue Loop
			}
			if postRegisterMsg(port) {
				lastRegTs = int64(time.Now().UnixMilli())
				continue Loop
			}
		}
	}
}

func postRegisterMsg(port string) (bool) {
	url := "http://" + config.Configuration.Server.Address + config.RegisterUri
	data := make(map[string]string)
	data["name"] = config.Configuration.Server.RegName
	data["ip"] = config.GetSelfIp()
	data["port"] = strings.Trim(port, ":") 
	data["agent"] = "ipscanner"
	data["hc_uri"] = "/-/healthy"
	jstr, err := json.Marshal(data)
	if err != nil {
		log.Panic("[Register] Serialization failed! " + err.Error())
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jstr))
	if err != nil {
		log.Errorf("[Register] Register failed, error: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", config.Configuration.Server.Authorization)
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Do(req)
	if nil != err {
		log.Errorf("[Register] Register failed, error: %v", err)
		return false
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		log.Errorf("[Register] Register failed, status code %v, error: %v", resp.StatusCode, string(msg))
		return false
	}
	log.Info("[Register] Registerred")
	return true
}

func StartMemoryCleaner() {
	timer := time.NewTimer(1 * time.Minute)
	timer2 := time.NewTimer(10 * time.Minute)
	for {
		timer.Reset(1 * time.Minute)
		timer2.Reset(10 * time.Minute)
		select {
		case <- timer.C:
			removeTasks(time.Now().Unix())
		case <- timer2.C:
			cleanMemory()
		}
	}
}

func removeTasks(timestamp int64) {
	for tid, taskContext := range finishedJob {
		if taskContext.Ondelete > 0 && timestamp > taskContext.Ondelete {
			removeTask(tid)
		}
	}
}

func cleanMemory() {
	newFinishedJob := make(map[string]*config.TaskContext)
	newRunningJob := make(map[string]*config.TaskContext)
	fjLock.Lock()
	for k := range finishedJob {
		delete(finishedJob, k)
	}
	finishedJob = nil
	finishedJob = newFinishedJob
	fjLock.Unlock()
	rjLock.Lock()
	for tid, taskContext := range runningJobPool {
		newRunningJob[tid] = taskContext
	}
	runningJobPool = nil
	runningJobPool = newRunningJob
	rjLock.Unlock()
	runtime.GC()
	log.Info("[clean] mem cleaned")
}