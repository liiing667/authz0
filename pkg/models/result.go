package models

const (
	MismatchNone           = ""
	MismatchOverPrivilege  = "over-privilege"
	MismatchUnderPrivilege = "under-privilege"
)

type Result struct {
	URL             string
	Method          string
	RoleName        string
	AllowRole       []string
	DenyRole        []string
	Assert          bool
	AssertAllowRole bool
	AssertDenyRole  bool
	StatusCode      int
	RespSize        int
	Alias           string
	Result          string
	Index           string
	Error           string
	MismatchType    string
}
