//go:build windows

package windows

import (
	"encoding/xml"
	"log"
	"testing"
	"time"

	"github.com/aws/amazon-cloudwatch-agent-test/internal/awsservice"
	"github.com/aws/amazon-cloudwatch-agent-test/internal/common"
	"github.com/stretchr/testify/assert"
)

const (
	configOutputPath = "/opt/aws/amazon-cloudwatch-agent/bin/config.json"
	agentRuntime     = 20 * time.Second // default flush interval is 5 seconds
)

// Event is the event entry representation
// Only the most common elements are processed, human-readable data is rendered in Message
// More info on schema, if there will be need to add more:
// https://docs.microsoft.com/en-us/windows/win32/wes/eventschema-elements
type Event struct {
	Source        Provider    `xml:"System>Provider"`
	EventID       int         `xml:"System>EventID"`
	Version       int         `xml:"System>Version"`
	Level         int         `xml:"System>Level"`
	Task          int         `xml:"System>Task"`
	Opcode        int         `xml:"System>Opcode"`
	Keywords      string      `xml:"System>Keywords"`
	TimeCreated   TimeCreated `xml:"System>TimeCreated"`
	EventRecordID int         `xml:"System>EventRecordID"`
	Correlation   Correlation `xml:"System>Correlation"`
	Execution     Execution   `xml:"System>Execution"`
	Channel       string      `xml:"System>Channel"`
	Computer      string      `xml:"System>Computer"`
	Security      Security    `xml:"System>Security"`
	UserData      UserData    `xml:"UserData"`
	EventData     EventData   `xml:"EventData"`
	Message       string
	LevelText     string
	TaskText      string
	OpcodeText    string
}

// UserData Application-provided XML data
type UserData struct {
	InnerXML []byte `xml:",innerxml"`
}

// EventData Application-provided XML data
type EventData struct {
	InnerXML []byte `xml:",innerxml"`
}

// Provider is the Event provider information
type Provider struct {
	Name string `xml:"Name,attr"`
}

// Correlation is used for the event grouping
type Correlation struct {
	ActivityID        string `xml:"ActivityID,attr"`
	RelatedActivityID string `xml:"RelatedActivityID,attr"`
}

// Execution Info for Event
type Execution struct {
	ProcessID   uint32 `xml:"ProcessID,attr"`
	ThreadID    uint32 `xml:"ThreadID,attr"`
	ProcessName string
}

// Security Data for Event
type Security struct {
	UserID string `xml:"UserID,attr"`
}

// TimeCreated field for Event
type TimeCreated struct {
	SystemTime string `xml:"SystemTime,attr"`
}

func TestWindowsEventLog(t *testing.T) {
	log.Printf("Testing Windows Plugin")
	cfgFilePath := "resources/config_windows_event_log.json"

	instanceId := awsservice.GetInstanceId()
	log.Printf("Found instance id %s", instanceId)
	logGroup := "CloudWatchAgent"
	logStream := instanceId

	start := time.Now()
	common.CopyFile(cfgFilePath, configOutputPath)

	common.StartAgent(configOutputPath, true)

	// ensure that there is enough time from the "start" time and the first log line,
	// so we don't miss it in the GetLogEvents call
	time.Sleep(agentRuntime)
	t.Log("Writing logs from windows event log plugin")
	time.Sleep(agentRuntime)
	common.StopAgent()

	end := time.Now()

	ok, err := awsservice.ValidateLogs(logGroup, logStream, &start, &end, func(logs []string) bool {
		log.Printf("logs length: %d ", len(logs))

		for i := 0; i < len(logs); i++ {
			log.Printf("logs[%d] is %s", i, logs[i])
			err := validateXML(logs[i])
			if err != nil {
				return false
			}
		}

		return true
	})
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestXML(t *testing.T) {
	log.Printf("Testing xml Plugin")
	logs := []string{
		"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7036</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2023-05-22T14:43:53.1670895Z'/><EventRecordID>64199</EventRecordID><Correlation/><Execution ProcessID='776' ThreadID='5788'/><Channel>System</Channel><Computer>EC2AMAZ-25GMQOK</Computer><Security/></System><EventData><Data Name='param1'>AppX Deployment Service (AppXSVC)</Data><Data Name='param2'>running</Data><Binary>41007000700058005300760063002F0034000000</Binary></EventData><RenderingInfo Culture='en-US'><Message>The AppX Deployment Service (AppXSVC) service entered the running state.</Message><Level>Information</Level><Task></Task><Opcode></Opcode><Channel></Channel><Provider>Microsoft-Windows-Service Control Manager</Provider><Keywords><Keyword>Classic</Keyword></Keywords></RenderingInfo></Event>",
	}
	assert.True(t, validateXML(logs[0]) == nil)
}

func validateXML(xmlString string) error {
	var event Event
	err := xml.Unmarshal([]byte(xmlString), &event)
	return err
}
