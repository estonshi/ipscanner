package tasks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	config "agents/ipscanner/config"

	"github.com/google/uuid"
)

var (
	rjLock sync.RWMutex
	runningJobPool map[string]*config.TaskContext = make(map[string]*config.TaskContext)
	fjLock sync.RWMutex
	finishedJob map[string]*config.TaskContext = make(map[string]*config.TaskContext)
)

/*
Submit job
*/
func JobSubmit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	t := query.Get("type")
	encrypt := query.Get("encrypt")
	var err error
	var tid string = ""
	if t == "ssh" {
		tid, err = submitSshJob(r)
	} else if t == "snmp" {
		tid, err = submitSnmpJob(r)
	} else if t == "arp" {
		tid, err = submitArpJob(r)
	} else {
		err = fmt.Errorf("unknown job type : %v", t)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		if encrypt == "y" {
			encBytes, err := config.AesEncrypt([]byte(tid))
			if nil != err {
				http.Error(w, fmt.Sprintf("data encryption error: %v", err), http.StatusInternalServerError)
				return
			}
			w.Write([]byte(encBytes))
		} else {
			w.Write([]byte(tid))
		}
	}
}

func submitSnmpJob(r *http.Request) (string, error) {
	bodyByte, err := getBody(r)
	if err != nil {
		return "", fmt.Errorf("body unserialization error : %v", err)
	}

	var taskInfo config.SNMPTask
	err = json.Unmarshal(bodyByte, &taskInfo)
	if err != nil {
		return "", fmt.Errorf("body unserialization error : %v", err)
	}
	// check scrape info
	invalidInfo := config.InvalidScrapeInfo(taskInfo.Info)
	if len(invalidInfo) > 0 {
		return "", fmt.Errorf("invalid scrape info : %v", invalidInfo)
	}
	// check task info
	if invalidSNMPTaskInfo(taskInfo) {
		return "", fmt.Errorf("submitted task info is invalid, please check")
	}

	// start goroutine
	taskContext, err := prepareContext(&taskInfo)
	if err != nil {
		return "", err
	}
	go startSNMPScanner(taskContext)
	return taskContext.Id, nil
}

func submitSshJob(r *http.Request) (string, error) {
	bodyByte, err := getBody(r)
	if err != nil {
		return "", fmt.Errorf("body unserialization error : %v", err)
	}

	var taskInfo config.SSHTask
	err = json.Unmarshal(bodyByte, &taskInfo)
	if err != nil {
		return "", fmt.Errorf("body unserialization error : %v", err)
	}

	// check scrape info
	invalidInfo := config.InvalidScrapeInfo(taskInfo.Info)
	if len(invalidInfo) > 0 {
		return "", fmt.Errorf("invalid scrape info : %v", invalidInfo)
	}
	// check task info
	if invalidSSHTaskInfo(taskInfo) {
		return "", fmt.Errorf("submitted task info is invalid, please check")
	}

	// start goroutine
	taskContext, err := prepareContext(&taskInfo)
	if err != nil {
		return "", err
	}
	go startSSHScanner(taskContext)
	return taskContext.Id, nil
}

func submitArpJob(r *http.Request) (string, error) {
	bodyByte, err := getBody(r)
	if err != nil {
		return "", fmt.Errorf("body unserialization error : %v", err)
	}

	var taskInfo config.ARPTask
	err = json.Unmarshal(bodyByte, &taskInfo)
	if err != nil {
		return "", fmt.Errorf("body unserialization error : %v", err)
	}
	// check task info
	if invalidARPTaskInfo(taskInfo) {
		return "", fmt.Errorf("submitted task info is invalid, please check")
	}

	// start goroutine
	taskContext, err := prepareContext(&taskInfo)
	if err != nil {
		return "", err
	}
	go startARPScanner(taskContext)
	return taskContext.Id, nil
}

func getBody(r *http.Request) ([]byte, error) {
	bodyByteEnc, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(bodyByteEnc) == 0 {
		return nil, errors.New("empty body")
	}

	bodyByte, errw := config.AesDecrypt(string(bodyByteEnc))
	if nil != errw {
		return nil, fmt.Errorf("decryption failed: %v", errw)
	}
	return bodyByte, nil
}

func prepareContext(taskInfo interface{}) (*config.TaskContext ,error) {
	rjLock.Lock()
	defer rjLock.Unlock()
	if len(runningJobPool) > config.Configuration.Api.Max_running {
		return nil, errors.New("the number of running jobs has reached max limit")
	}
	taskContext, err := newTaskContext(taskInfo)
	if err != nil {
		return nil, err
	}
	runningJobPool[taskContext.Id] = taskContext
	return taskContext, nil
}

func newTaskContext(submitInfo interface{}) (*config.TaskContext, error) {
	var taskContext *config.TaskContext = new(config.TaskContext)
	taskContext.Id = uuid.New().String()
	if taskContext.Id == "" {
		return nil, errors.New("failed to generate task id")
	}
	taskContext.StartsAt = time.Now().Unix()
	taskContext.SubmitInfo = submitInfo
	switch v := submitInfo.(type) {
	case *config.SSHTask:
		taskContext.TaskType = "SSH"
	case *config.SNMPTask:
		taskContext.TaskType = "SNMP"
	case *config.ARPTask:
		taskContext.TaskType = "ARP"
	default:
		return nil, fmt.Errorf("unknown task type: %v", v)
	}
	return taskContext, nil
}

func finishTask(id string) {
	taskContext, ok := runningJobPool[id]
	if !ok {
		return
	}
	fjLock.Lock()
	defer fjLock.Unlock()
	rjLock.Lock()
	defer rjLock.Unlock()
	finishedJob[id] = taskContext
	delete(runningJobPool, id)
}

func removeTask(id string) {
	_, ok := finishedJob[id]
	if !ok {
		return
	}
	fjLock.Lock()
	defer fjLock.Unlock()
	delete(finishedJob, id)
}

/*
For scanner
*/

func initT(task *config.TaskContext) {
	task.Status = "Created"
	config.Tst <- task
}

func updateT(task *config.TaskContext, result []*config.Item) {
	task.Result = result
}

func finishT(task *config.TaskContext, result []*config.Item, err error) {
	task.EndsAt = time.Now().Unix()
	if nil == err {
		task.Status = "Finished"
	} else {
		task.Status = "Failed"
		task.Message = err.Error()
	}
	task.Result = result
	finishTask(task.Id)
	config.Tst <- task
}


/*
Query job result
*/
func GetResult(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	tid := query.Get("id")
	encrypt := query.Get("encrypt")
	taskResult, ok := finishedJob[tid]
	if !ok {
		taskResult, ok = runningJobPool[tid]
		if !ok {
			http.Error(w, "", http.StatusForbidden)
			return
		}
	}
	bytes, err := json.Marshal(taskResult)
	if err != nil {
		http.Error(w, fmt.Sprintf("data serialization error: %v", err), http.StatusInternalServerError)
		return
	}
	if encrypt == "y" {
		encBytes, err := config.AesEncrypt(bytes)
		if nil != err {
			http.Error(w, fmt.Sprintf("data encryption error: %v", err), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(encBytes))
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		w.Write(bytes)
	}
	if taskResult.Status == "Finished" || taskResult.Status == "Failed" {
		taskResult.Ondelete = time.Now().Add(time.Duration(config.Configuration.Api.CacheTime) * time.Minute).Unix()
	}
}