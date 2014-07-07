package jbxcloud

import "testing"
import "fmt"

// Private Username and Password
var username string = ""
var password string = ""

func TestAvaiable(t *testing.T) {

    joebox := Client{Username: username, Password: password}
    joebox.UseDefaultUrl()

    if a, err := joebox.IsAvaliable(); err != nil {
        t.Errorf("Got err: ", err)
    } else {
        fmt.Printf("Joebox is available?: %v\n", a)
    }

}

func TestSystems(t *testing.T) {
    joebox := Client{Username: username, Password: password}
    joebox.UseDefaultUrl()

    if _, err := joebox.GetSystems(); err != nil {
        t.Errorf("Got err: ", err)
    } else {
    }
}
