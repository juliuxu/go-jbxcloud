package jbxcloud

import "net/http"
import "net/url"
import "fmt"

// import "path/filepath"
// import "mime/multipart"

const defaultUrl string = "https://jbxcloud.joesecurity.org/index.php/api/"

// Client interacts with services provided by jbxcloud
type Client struct {
    Username string
    Password string
    Url string
}

// Use Default URL
func (self *Client) UseDefaultUrl() {
    self.Url = defaultUrl
}

// Check if Joe Sandbox is available or in maintenance mode
func (self *Client) IsAvaliable() (bool, error) {


    // Set Parameters
    values := url.Values{}
    values.Set("username", self.Username)
    values.Set("password", self.Password)

    // Set fullurl
    fullUrl := self.Url + "server/available"

    // Perform post request
    resp, err := http.PostForm(fullUrl, values)
    if err != nil {
        return false, err
    }

    if resp.StatusCode == 403 {
        return false, fmt.Errorf("Status code 403")
    }

    return true, nil
}

// Get a list of available analysis system
func (self *Client) GetSystems() (bool, error) {
    return true, nil
}


// Get the size of the submission queue
func (self *Client) GetSize() (int64, error) {
    return 0, nil
}
