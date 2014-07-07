package jbxcloud

import "net/http"
import "net/url"
import "fmt"
import "io/ioutil"
import "encoding/json"
import "strconv"

// import "path/filepath"
// import "mime/multipart"

const defaultUrl string = "https://jbxcloud.joesecurity.org/index.php/api/"

// Client interacts with services provided by jbxcloud
type Client struct {
	Username string
	Password string
	Url      string
}

// Use Default URL
func (self *Client) UseDefaultUrl() {
	self.Url = defaultUrl
}

// Perform post request
func (self *Client) makePost(action string, parameters map[string]string) (*http.Response, error) {

	// Set Parameters
	values := url.Values{}
	values.Set("username", self.Username)
	values.Set("password", self.Password)
	for k, v := range parameters {
		values.Add(k, v)
	}

	// Set fullurl
	fullUrl := self.Url + action

	// Perform post request
	resp, err := http.PostForm(fullUrl, values)
	if err != nil {
		return nil, err
	}

	// Catch 403 forbidden
	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("HTTP error 403 (Forbidden) for wrong username/password")
	}

	// Catch 503 Service Unavailable
	if resp.StatusCode == 503 {
		return nil, fmt.Errorf("HTTP error 503 (Service Unavailable) system is in maintenance mode")
	}

	return resp, nil

}

// Check if Joe Sandbox is available or in maintenance mode
func (self *Client) IsAvaliable() (bool, error) {

	// Perform post request
	resp, err := self.makePost("server/available", map[string]string{})
	if err != nil {
		return false, err
	}

	// Parse response
	content, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, err
	}
	if string(content) == "1" {
		return true, nil
	} else if string(content) == "0" {
		return false, nil
	} else {
		return false, fmt.Errorf("result is neither 0 or 1")
	}
}

/*
  "name": "xp",
  "description": "XP SP3 (Office 2003 SP2, Java 1.6.0, Acrobat Reader 9.3.4, Internet Explorer 8)",
  "arch": "WINDOWS",
  "count": 1
*/
type JoeBoxSystem struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Arch        string `json:"arch"`
	count       int    `json:"count"`
}

// Get a list of available analysis systems
func (self *Client) GetSystems() (*[]JoeBoxSystem, error) {
	// Perform post request
	resp, err := self.makePost("server/systems", map[string]string{})
	if err != nil {
		return nil, err
	}

	// Parse response
	var content []JoeBoxSystem
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, err
	}

	return &content, nil
}

// Get the size of the submission queue
func (self *Client) GetSize() (int64, error) {

	// Perform post request
	resp, err := self.makePost("queue/size", map[string]string{})
	if err != nil {
		return -1, err
	}

	// Parse response
	content, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return -1, err
	}

	size, err := strconv.ParseInt(string(content), 10, 0)
	if err != nil {
		return -1, err
	}

	return size, nil
}

/*
  "webid": "48284",
  "md5": "",
  "filename": "www.somethingbadasdasd.com\/main.swf",
  "scriptname": "browseieffchrome.jbs",
  "time": "1404727472",
  "status": "finished",
  "reportid": "45106",
  "comments": "",
  "systems": "xp3;xp3;xp3;",
  "detections": "0;0;0;",
  "errors": ";;;",
  "runnames": ";;;",
  "yara": "false;false;false;"
*/
type JoeBoxAnalsis struct {
	Webid      string `json:"webid"`
	Md5        string `json:"md5"`
	Filename   string `json:"filename"`
	Scriptname string `json:"scriptname"`
	Time       string `json:"time"`
	Status     string `json:"status"`
	ReportId   string `json:"reportid"`
	Comments   string `json:"comments"`
	Systems    string `json:"systems"`
	Detections string `json:"detections"`
	Errors     string `json:"errors"`
	Runnames   string `json:"runnames"`
	Yara       string `json:"yara"`
}

// Get a list of analyses
func (self *Client) ListAnalyses() (*[]JoeBoxAnalsis, error) {

	// Perform post request
	resp, err := self.makePost("analysis/list", map[string]string{})
	if err != nil {
		return nil, err
	}

	// Parse response
	var content []JoeBoxAnalsis
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, err
	}

	return &content, nil

}
