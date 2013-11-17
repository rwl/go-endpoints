package endpoints

import (
	"encoding/json"
	"errors"
//	"fmt"
	"net/http"
//	"strings"

	//"appengine"
	"github.com/golang/glog"
)

// Levels that can be specified for a LogMessage.
type logLevel string

const (
	levelDebug    logLevel = "debug"
	levelInfo     logLevel = "info"
	levelWarning  logLevel = "warning"
	levelError    logLevel = "error"
	levelCritical logLevel = "critical"
)

// Request body for fetching API configs.
type GetApiConfigsRequest struct {
	AppRevision string `json:"appRevision"`
}

// List of API configuration file contents.
type ApiConfigsList struct {
	Items []string `json:"items"`
}

// Request body for log messages sent by Swarm FE.
type LogMessagesRequest struct {
	Messages []*LogMessage `json:"messages"`
}

// A single log message within a LogMessagesRequest.
type LogMessage struct {
	Level   logLevel `json:"level"`
	Message string   `json:"message" endpoints:"required"`
}

// API config enumeration service used by Google API Server.
// 
// This is a simple API providing a list of APIs served by this App Engine
// instance. It is called by the Google API Server during app deployment
// to get an updated interface for each of the supported APIs.
type BackendService struct {
	server *Server // of which server
}

// GetApiConfigs creates ApiDescriptor for every registered RpcService and
// responds with a config suitable for generating Discovery doc.
// 
// Responds with a list of active APIs and their configuration files.
func (s *BackendService) GetApiConfigs(r *http.Request, req *GetApiConfigsRequest, resp *ApiConfigsList) error {

	/*if req.AppRevision != "" {
		c := appengine.NewContext(r)
		revision := strings.Split(appengine.VersionID(c), ".")[1]
		if req.AppRevision != revision {
			return fmt.Errorf(
				"API backend app revision %s not the same as expected %s",
				revision, req.AppRevision)
		}
	}*/

	resp.Items = make([]string, 0)
	for _, service := range s.server.services.services {
		if service.internal {
			continue
		}
		d := &ApiDescriptor{}
		if err := service.ApiDescriptor(d, r.Host); err != nil {
			return err
		}
		bytes, err := json.Marshal(d)
		if err != nil {
			return err
		}
		resp.Items = append(resp.Items, string(bytes))
	}
	return nil
}

// LogMessages writes a log message from the Swarm FE to the log.
func (s *BackendService) LogMessages(r *http.Request, req *LogMessagesRequest, _ *VoidMessage) error {

	//c := appengine.NewContext(r)
	for _, msg := range req.Messages {
		writeLogMessage(msg.Level, msg.Message)
	}
	return nil
}

// This is a test method and will be removed sooner or later.
func (s *BackendService) GetFirstConfig(r *http.Request, _ *VoidMessage, resp *ApiDescriptor) error {

	for _, service := range s.server.services.services {
		if !service.internal {
			return service.ApiDescriptor(resp, r.Host)
		}
	}
	return errors.New("Not Found: No public API found")
}

func writeLogMessage(level logLevel, msg string) {
	const fmt = "%s"
	switch level {
	case levelDebug:
		glog.Infof(fmt, msg)
	case levelWarning:
		glog.Warningf(fmt, msg)
	case levelError:
		glog.Errorf(fmt, msg)
	case levelCritical:
		glog.Fatalf(fmt, msg)
	default:
		glog.Infof(fmt, msg)
	}
}

func newBackendService(server *Server) *BackendService {
	return &BackendService{server: server}
}
