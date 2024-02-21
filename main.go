package main

import (
	"fmt"
	"net/http"
	"os"

	config "agents/ipscanner/config"
	tasks "agents/ipscanner/tasks"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const version string = "1.0.0"

var (
	showVersion   = kingpin.Flag("version", "Print version information").Default().Bool()
	listenAddress = kingpin.Flag("web.listen-address", "Address on which to expose metrics and web interface").Default(":9921").String()
	logLevel      = kingpin.Flag("log.level", "Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]").Default("info").String()
	configFile    = kingpin.Flag("config", "Path of config file, default='config.yml'").Default("config.yml").String()
)

func main() {

	kingpin.Parse()

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	setLogLevel(*logLevel)
	log.SetReportCaller(true)
	log.Infof("Starting ip scanner (Version: %s)", version)

	err := config.LoadFile(*configFile)
	if nil != err {
		log.Error(err)
		os.Exit(1)
	}

	// start prometheus handler go routine
	config.InitTaskStatusChan()
	go ListenTaskStatus()

	// start registration
	if config.Configuration.Server.Register {
		go tasks.StartRegistration(*listenAddress)
	}

	// start mem cleaner
	go tasks.StartMemoryCleaner()

	// Normal metrics endpoint for exporter
	http.Handle("/metrics", promhttp.Handler())
	// Endpoint for submitting job  /submit?type=
	http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "", http.StatusMethodNotAllowed)
		} else {
			tasks.JobSubmit(w, r)
		}
	})
	// Endpoint for query result  /result?id=
	http.HandleFunc("/result", func(w http.ResponseWriter, r *http.Request) {
		tasks.GetResult(w, r)
	})
	// Endpoint for health check
	http.HandleFunc("/-/healthy", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "active", http.StatusOK)
	})

	// listen
	server := http.Server{
		Addr: *listenAddress,
	}
	log.Infof("Listening on %s (HTTP)", *listenAddress)
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

}

func printVersion() {
	fmt.Println("ipscanner")
	fmt.Printf("Version: %s\n", version)
	fmt.Println("Author(s): ctdi")
	fmt.Println("IP scanner by ssh/snmp")
}

func setLogLevel(l string) {
	switch l {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}
