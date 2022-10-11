package model

/*
	Data representing a decision made by Crowdsec
*/
type Decision struct {
	Id        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

type Stream struct {
	Deleted []Decision 	`json:"deleted"`
	New     []Decision 	`json:"new"`
}
