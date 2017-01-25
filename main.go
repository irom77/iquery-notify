package main

import (
	"log"

	"github.com/influxdata/influxdb/client/v2"
	"fmt"
	"time"
	"flag"
	"os"
)

var (
	URL = flag.String("url", "http://10.73.21.205:8086", "InfluxDB url")
	DB = flag.String("db", "syslog", "Database name")
	USER = flag.String("user", "firewall", "Username")
	TIME = flag.Duration("time", 1, "time back in minutes ")
	PASSWORD= flag.String("password", "password", "Password")
	version = flag.Bool("v", false, "Prints current version")
)
var (
	Version = "No Version Provided"
	BuildTime = ""
)

func init() {
	flag.Usage = func() {
		fmt.Printf("Copyright 2017 @IrekRomaniuk. All rights reserved.\n")
		fmt.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *version {
		fmt.Printf("App Version: %s\nBuild Time : %s\n", Version, BuildTime)
		os.Exit(0)
	}
}

// queryDB convenience function to query the database
func queryDB(clnt client.Client, cmd string) (res []client.Result, err error) {
	q := client.Query{
		Command:  cmd,
		Database: *DB,
	}
	if response, err := clnt.Query(q); err == nil {
		if response.Error() != nil {
			return res, response.Error()
		}
		res = response.Results
	} else {
		return res, err
	}
	return res, nil
}

func main () {
	// Create a new HTTPClient
	c, err := client.NewHTTPClient(client.HTTPConfig{
	Addr:     *URL,
	Username: *USER,
	Password: *PASSWORD,
	})
	if err != nil {
	log.Fatal(err)
	}

	//Find last records
	layout := "2006-01-02 15:04:05"
	t := time.Now()
	t1 := t.Format(layout)
	t2 := t.Add(-*TIME*time.Minute).Format(layout)
	// test with ./syslog-generator -ip="10.34.1.100" -port="11514" -protocol="udp"
	q := fmt.Sprintf("SELECT SrcIP,DstIP,DstPort,App,ThreatType,Severity,Action,ThreatName" +
		" FROM logstash WHERE time > '" + t2 + "' AND time < '" + t1 + "'")
	//fmt.Println("t:",t,"\nt1:",t1,"\nt2:",t2,"\n",q)
	res, err := queryDB(c, q)
	if err != nil {
		log.Fatal(err)
	}

	for i, row := range res[0].Series[0].Values {
		t, err := time.Parse(time.RFC3339, row[0].(string))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[%2d] %15s: %-15v %-15v %-7v %-15v %-15v %-10v %-10v %-10v\n", i, t.Format(time.Stamp),
			row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8])
	}
	fmt.Printf("[%2s] %-15s: %-15v %-15v %-7v %-15v %-15v %-10v %-10v %-10v\n","No", "time",
		"SrcIP","DstIP", "DstPort","App","ThreatType","Severity","Action","ThreatName")
}

