package jbxcloud

import "net/http"
import "net/url"
import "fmt"
import "io/ioutil"
import "encoding/json"

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
	return 0, nil
}
