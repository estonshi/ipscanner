package main

import (
	"agents/ipscanner/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

var (

	// Metrics about the agent itself.
	scanTaskTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ipscan_task_executed_total",
			Help: "The total number of tasks this agent has ever started",
		},
	)

	scanTaskRunning = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ipscan_task_running",
			Help: "The number of tasks that are currently running on this agent",
		},
	)

	scanTaskFinished = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ipscan_task_finished_total",
			Help: "The total number of tasks that successfully finished on this agent",
		},
	)

	scanTaskFailed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ipscan_task_failed_total",
			Help: "The total number of tasks that ran into error on this agent",
		},
	)

	scanTaskDuration = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ipscan_task_duration_sec_total",
			Help: "The accumulated execution time of all finished tasks, in seconds",
		},
	)
)

func promTaskStart() {
	scanTaskTotal.Inc()
	scanTaskRunning.Inc()
}

func promTaskFinished(duration int64) {
	scanTaskRunning.Dec()
	scanTaskDuration.Add(float64(duration))
	scanTaskFinished.Inc()
}

func promTaskFailed() {
	scanTaskRunning.Dec()
	scanTaskFailed.Inc()
}

func ListenTaskStatus() {
	for task := range config.Tst {
		switch task.Status {
		case "Created":
			promTaskStart()
		case "Finished":
			promTaskFinished(task.EndsAt-task.StartsAt)
		case "Failed":
			promTaskFailed()
		default:
			log.Errorf("Invalid task status : %v", task.Status)
		}
	}
}