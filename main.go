package main

import (
	"log"
	"gopkg.in/gomail.v2"
	"github.com/influxdata/influxdb/client/v2"
	"fmt"
	"time"
	"flag"
	"os"
	"crypto/tls"
	"html/template"
	"bytes"
	"strconv"
)

var (
	URL = flag.String("url", "http://influx:8086", "InfluxDB url")
	DB = flag.String("db", "syslog", "Database name")
	USER = flag.String("user", "firewall", "Username")
	TIME = flag.Int("time", 1, "time back in minutes ")
	PASSWORD= flag.String("password", "password", "Password")
	FROM = flag.String("from", "logstash@", "Email from")
	TO = flag.String("to", "me@", "Email to")
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

type Threat struct {
	SrcIP,DstIP, DstPort,App,ThreatType,Severity,Action,ThreatName string
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
	//fmt.Println(*URL, *USER, *PASSWORD, *FROM, *TO)
	// Create a new HTTPClient
	c, err := client.NewHTTPClient(client.HTTPConfig{
	Addr:     *URL,
	Username: *USER,
	Password: *PASSWORD,
	})
	if err != nil {
	log.Fatal("can't create db conn",err)
	}
	//Find last records
	layout := "2006-01-02 15:04:05"
	t := time.Now().UTC()
	t1 := t.Format(layout)
	t2 := t.Add(-time.Duration(*TIME)*time.Minute).Format(layout)
	// test with ./syslog-generator -ip="10.34.1.100" -port="11514" -protocol="udp"
	q := fmt.Sprintf("SELECT SrcIP,DstIP,DstPort,App,ThreatType,Severity,Action,ThreatName" +
		" FROM logstash WHERE time > '" + t2 + "' AND time < '" + t1 + "'")
	fmt.Println(q)
	res, err := queryDB(c, q)
	if err != nil {
		log.Fatal("can't connect to db",err)
	}
	var Threats []Threat
	for _, row := range res[0].Series[0].Values {
		Threats = append(Threats,Threat{row[1].(string), row[2].(string), row[3].(string), row[4].(string),
			row[5].(string), row[6].(string), row[7].(string), row[8].(string)})
	}
	buf := new(bytes.Buffer)
	th := template.Must(template.New("html table").Parse(tmplhtml))
	err = th.Execute(buf, Threats)
	if err != nil {
		log.Fatalf("can't html", err)
	}
	htmlbody := buf.String()
	err = notify(strconv.Itoa(len(Threats)), htmlbody, *FROM, *TO, *TIME)
	if err != nil {
		log.Fatalf("can't notify", err)
	}
}
//Notify by email
func notify(count, body, from, to string, time int) error {
	m := gomail.NewMessage()
	m.SetHeader("From",from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", " THREAT count: " + count + " in last " + strconv.Itoa(time) + " min")
	m.SetBody("text/html", body)
	//fmt.Printf("\nSending email notification to %s:\n", to)
	d := gomail.Dialer{Host: "relay", Port: 25}
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}

const tmplhtml = `
	<style>
	table, th, td {
   	border: 1px solid black;
	}
	</style>
	<table>
	<tr style='text-align: left'>
  	<th>SrcIP</th>
  	<th>DstIP</th>
  	<th>DstPort</th>
  	<th>App</th>
  	<th>ThreatType</th>
  	<th>Severity</th>
  	<th>Action</th>
  	<th>ThreatName</th>
	</tr>
	{{range .}}
	<tr>
	<td>{{.SrcIP}}</td>
	<td>{{.DstIP}}</td>
	<td>{{.DstPort}}</td>
	<td>{{.App}}</td>
	<td>{{.ThreatType}}</td>
	<td>{{.Severity}}</td>
	<td>{{.Action}}</td>
	<td>{{.ThreatName}}</td>
	{{end}}
	</table>
	`