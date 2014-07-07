package jbxcloud

import "net/http"
import "net/url"
import "bytes"
import "mime/multipart"
import "fmt"
import "io/ioutil"
import "encoding/json"
import "strconv"
import "os"
import "io"
import "path/filepath"

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

	// Catch 400 (Bad request)
	if resp.StatusCode == 400 {
		return nil, fmt.Errorf("HTTP error 400 (Bad request) for missing parameters or wrong values")
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
type JoeBoxAnalysis struct {
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
func (self *Client) ListAnalyses() (*[]JoeBoxAnalysis, error) {

	// Perform post request
	resp, err := self.makePost("analysis/list", map[string]string{})
	if err != nil {
		return nil, err
	}

	// Parse response
	var content []JoeBoxAnalysis
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, err
	}

	return &content, nil

}

// Check the status of an analysis
func (self *Client) CheckAnalysis(webid string) (*JoeBoxAnalysis, error) {

	// Perform post request
	resp, err := self.makePost("analysis/check", map[string]string{"webid": webid})
	if err != nil {
		return nil, err
	}

	// Parse response
	content := JoeBoxAnalysis{}
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, err
	}

	return &content, nil

}

// Main JoeBox Analysis result struct
type JoeBoxAnalysisResult struct {
	GeneralInfo struct {
		Version    string `json:"version"`
		Id         int    `json:"id"`
		Starttime  string `json:"starttime"`
		Product    string `json:"product"`
		Startdate  string `json:"startdate"`
		Duration   string `json:"duration"`
		Reporttype string `json:"reporttype"`
		Target     struct {
			Sample         string `json:"sample"`
			Cookbook       string `json:"cookbook"`
			Submissionpath string `json:"submissionpath"`
		} `json:"target"`

		Systemdescription string `json:"systemdescription"`
		Arch              string `json:"arch"`
	} `json:"generalinfo"`

	FileInfo struct {
		Filetype       string `json:"filetype"`
		Filename       string `json:"filename"`
		Submissionpath string `json:"submissionpath"`
		Filesize       int    `json:"filesize"`
		Md5            string `json:"md5"`
		Sha1           string `json:"sha1"`
		Sha256         string `json:"sha256"`
		Sha512         string `json:"sha512"`
	} `json:"fileinfo"`

	// Behavior      struct{} `json:"behavior"`

	SignatureInfo struct {
		Sig []struct {
			Impact      string `json:"@impact"`
			Basedoncode string `json:"@basedoncode"`
			Id          string `json:"@id"`
			Desc        string `json:"@desc"`
			Types       string `json:"@types"`

			// These fields can both be object or array, bad..
			// Sources     struct {
			// 	Source struct {
			// 		Id      string `json:"@id"`
			// 		Op      string `json:"@op"`
			// 		Process string `json:"@process"`
			// 		Dollar  string `json:"$"`
			// 	} `json:"source"`
			// } `json:"sources"`

		} `json:"sig"`
	} `json:"signatureinfo"`

	// PatternInfo   struct{} `json:"patterninfo"`

	SignatureDetections struct {
		Strategy []struct {
			Name   string `json:"name"`
			Count  string `json:"count"`
			Dollar string `json:"$"`
		} `json:"strategy"`
	} `json:"signaturedetections"`

	DroppedInfo struct {
		Hash []struct {
			File  string `json:"@file"`
			Type  string `json:"@type"`
			Value []struct {
				Algo   string `json:"@algo"`
				Dollar string `json:"$"`
			} `json:"value"`
		} `json:"hash"`
	} `json:"droppedinfo"`

	Sigscore struct {
		Score []struct {
			Name        string `json:"@name"`
			Id          string `json:"@id"`
			Impactlevel string `json:"@impactlevel"`
			Dollar      string `json:"$"`
		} `json:"score"`
	} `json:"sigscore"`

	FuncStats struct {
		Func []struct {
			Name   string `json:"@name"`
			Dollar string `json:"$"`
		} `json:"func"`
	} `json:"funcstats"`

	// TODO: More, and more complete
}

// Get analysis results (just json for now)
func (self *Client) GetAnalysisResults(webid string) (*JoeBoxAnalysisResult, error) {

	// Perform post request
	resp, err := self.makePost("analysis/download", map[string]string{"webid": webid, "type": "json"})
	if err != nil {
		return nil, err
	}

	// Parse response
	contentWrapper := struct {
		Content JoeBoxAnalysisResult `json:"analysis"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&contentWrapper); err != nil {
		return nil, err
	}

	return &contentWrapper.Content, nil

}

// Submit a file
func (self *Client) SubmitFile(file string, systems []string, allowinet bool, useSCAE bool) (string, error) {

	// Make sure at least one system has been chosen
	if len(systems) == 0 {
		return "", fmt.Errorf("must choose a system to run analysis on!")
	}

	// Create file buffer
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	// Add the file
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	fw, err := w.CreateFormFile("sample", filepath.Base(file))
	if err != nil {
		return "", err
	}
	if _, err = io.Copy(fw, f); err != nil {
		return "", err
	}

	// Add the other fields
	parameters := map[string]string{
		"username": self.Username,
		"password": self.Password,
		"type":     "file",
		"tandc":    "1", // Accept terms
	}
	for k, v := range parameters {
		w.WriteField(k, v)
	}

	// Enable systems
	for _, system := range systems {
		w.WriteField(system, "1")
	}

	// Optional fields
	if allowinet {
		w.WriteField("inet", "1")
	}
	if useSCAE {
		w.WriteField("scae", "1")
	}

	// Close the writer
	w.Close()

	// Create new request
	req, err := http.NewRequest("POST", self.Url+"analysis", &b)
	if err != nil {
		return "", err
	}
	// Set Content-Type
	req.Header.Set("Content-Type", w.FormDataContentType())

	// Submit the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	// Catch errors
	if resp.StatusCode == 403 {
		return "", fmt.Errorf("HTTP error 403 (Forbidden) for wrong username/password")
	} else if resp.StatusCode == 503 {
		return "", fmt.Errorf("HTTP error 503 (Service Unavailable) system is in maintenance mode")
	} else if resp.StatusCode == 400 {
		return "", fmt.Errorf("HTTP error 400 (Bad request) for missing parameters or wrong values")
	}

	// Parse response
	webidstruct := struct {
		Webid int `json:"webid"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&webidstruct); err != nil {
		return "", err
	}

	return strconv.Itoa(webidstruct.Webid), nil
}
