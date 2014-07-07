package jbxcloud

import "testing"

// Private Username and Password
// IMPORTTANT: DO NOT GIT COMMIT AND/OR PUSH UP WHILE THESE LINES ARE NOT EMPTY!!!
var username string = ""
var password string = ""

func TestAvaiable(t *testing.T) {

	joebox := Client{Username: username, Password: password}
	joebox.UseDefaultUrl()

	if _, err := joebox.IsAvaliable(); err != nil {
		t.Errorf("Got err: %v", err)
	} else {
		// fmt.Printf("Joebox is available?: %v\n", a)
	}

}

func TestSystems(t *testing.T) {
	joebox := Client{Username: username, Password: password}
	joebox.UseDefaultUrl()

	if _, err := joebox.GetSystems(); err != nil {
		t.Errorf("Got err: %v", err)
	} else {
		// fmt.Printf("response: %v\n", v)
	}
}

func TestSize(t *testing.T) {
	joebox := Client{Username: username, Password: password}
	joebox.UseDefaultUrl()

	if _, err := joebox.GetSize(); err != nil {
		t.Errorf("Got err: %v", err)
	} else {
		// fmt.Printf("response: %v\n", v)
	}
}

func TestListAnalysis(t *testing.T) {
	joebox := Client{Username: username, Password: password}
	joebox.UseDefaultUrl()

	if _, err := joebox.ListAnalyses(); err != nil {
		t.Errorf("Got err: %v", err)
	} else {
		// fmt.Printf("response: %v\n", v)
	}
}

func TestCheckAnalysis(t *testing.T) {
	joebox := Client{Username: username, Password: password}
	joebox.UseDefaultUrl()

	if _, err := joebox.CheckAnalysis("48284"); err != nil {
		t.Errorf("Got err: %v", err)
	} else {
		// fmt.Printf("response: %v\n", v)
	}
}

func TestGetAnalysisResults(t *testing.T) {
	joebox := Client{Username: username, Password: password}
	joebox.UseDefaultUrl()

	if _, err := joebox.GetAnalysisResults("47865"); err != nil {
		t.Errorf("Got err: %v", err)
	} else {
		// fmt.Printf("response: %v\n", v)
	}
}

func TestSubmitFile(t *testing.T) {
	joebox := Client{Username: username, Password: password}
	joebox.UseDefaultUrl()

	if _, err := joebox.SubmitFile("putty.exe", []string{"xp"}, true, true); err != nil {
		t.Errorf("Got err: %v", err)
	} else {
		// fmt.Printf("response: %v\n", v)
	}
}
