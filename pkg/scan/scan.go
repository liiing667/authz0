package scan

import (
	"strconv"
	"strings"
	"sync"

	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/logger"
	"github.com/hahwul/authz0/pkg/models"
	"github.com/hahwul/authz0/pkg/utils"
	"github.com/sirupsen/logrus"
)

type ScanArguments struct {
	RoleName     string
	Cookie       string
	Headers      []string
	Concurrency  int
	Delay        int
	Timeout      int
	ProxyAddress string
}

type Query struct {
	Index int
	Query models.URL
}

func Run(filename string, arguments ScanArguments, debug bool) []models.Result {
	log := logger.GetLogger(debug)
	queries := make(chan Query)
	template := authz0.FileToTemplate(filename)
	log.Info("loaded testing template: " + template.Name)
	if arguments.RoleName != "" {
		log.Info("append credential to template [" + arguments.RoleName + " role]")
		tCred := models.Credential{
			Rolename: arguments.RoleName,
			Headers:  arguments.Headers,
		}
		template.Credentials = append(template.Credentials, tCred)
	}
	credCount := len(template.Credentials)
	// Pre-allocate one slot per (URL, credential) pair so every worker
	// writes to its own index. This keeps the output ordered by template
	// URLs and role declaration order regardless of concurrency.
	results := make([]models.Result, len(template.URLs)*credCount)
	var wg sync.WaitGroup
	for i := 0; i < arguments.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for query := range queries {
				reqURL := query.Query
				for credIndex, cred := range template.Credentials {
					result := checkEndpoint(reqURL, query.Index, cred, arguments, template, log)
					results[query.Index*credCount+credIndex] = result
				}
			}
		}()
	}
	log.Info("targets:  " + strconv.Itoa(len(template.URLs)) + " URLs")
	for index, endpoint := range template.URLs {
		q := Query{
			Index: index,
			Query: endpoint,
		}
		queries <- q
	}
	close(queries)
	wg.Wait()
	return results
}

func checkEndpoint(reqURL models.URL, index int, cred models.Credential, arguments ScanArguments, template models.Template, log *logrus.Logger) models.Result {
	result := models.Result{
		URL:       reqURL.URL,
		Method:    reqURL.Method,
		RoleName:  cred.Rolename,
		AllowRole: reqURL.AllowRole,
		DenyRole:  reqURL.DenyRole,
		Alias:     reqURL.Alias,
		Result:    "O",
		Index:     "#" + strconv.Itoa(index),
	}
	iLog := log.WithField("index", result.Index)
	if result.Alias != "" {
		iLog.Info("check '" + result.Alias + "'")
	} else {
		iLog.Info("check '" + result.URL + "'")
	}

	res, cl, err := sendReq(reqURL, arguments, template, cred.Headers)
	if err != nil {
		// Request failure is recorded separately from assertion and
		// role-policy failures.
		result.Error = err.Error()
		result.Result = "X"
		iLog.WithFields(logrus.Fields{
			"url":  result.Method + " " + result.URL,
			"type": "request",
		}).WithError(err).Error("request failed")
		return result
	}
	result.StatusCode = res.StatusCode
	result.RespSize = cl

	check := checkAssert(res, template.Asserts, cl)
	result.Assert = check

	rltValue := true
	if cred.Rolename != "" {
		if check {
			if len(reqURL.AllowRole) > 0 {
				if utils.ContainsFromArray(reqURL.AllowRole, cred.Rolename) {
					result.AssertAllowRole = true
					rltValue = rltValue && true
				} else {
					rltValue = rltValue && false
				}
			}
			if len(reqURL.DenyRole) > 0 {
				if utils.ContainsFromArray(reqURL.DenyRole, cred.Rolename) {
					result.AssertDenyRole = false
					rltValue = rltValue && false
				} else {
					rltValue = rltValue && true
				}
			}
		} else {
			if len(reqURL.AllowRole) > 0 {
				if utils.ContainsFromArray(reqURL.AllowRole, cred.Rolename) {
					result.AssertAllowRole = true
					rltValue = rltValue && false
				} else {
					rltValue = rltValue && true
				}
			}
			if len(reqURL.DenyRole) > 0 {
				if utils.ContainsFromArray(reqURL.DenyRole, cred.Rolename) {
					result.AssertDenyRole = true
					rltValue = rltValue && true
				}
			}
		}
		if !rltValue {
			result.Result = "X"
			if check {
				// Access succeeded where policy expects denial (越权)
				result.MismatchType = models.MismatchOverPrivilege
			} else {
				// Access denied where policy expects allowance (漏权)
				result.MismatchType = models.MismatchUnderPrivilege
			}
		}
	}

	uLog := iLog.WithFields(logrus.Fields{
		"url":  result.Method + " " + result.URL,
		"type": "assert",
	})
	uLog.Info("response code: " + strconv.Itoa(result.StatusCode))
	if result.Assert {
		uLog.Info("assertion: hit")
	} else {
		if cred.Rolename == "" {
			uLog.WithField("assertion", "assertion: fail").Warn("found assert fail")
		} else {
			uLog.Info("assertion: fail")
		}
	}
	rLog := iLog.WithFields(logrus.Fields{
		"type": "role-test",
	})
	ar := strings.Join(result.AllowRole, ",")
	dr := strings.Join(result.DenyRole, ",")
	if ar == "" {
		ar = "<allow-all>"
	}
	if dr == "" {
		dr = "<not-deny>"
	}
	rLog.Info("allow-role: " + ar)
	rLog.Info("deny-role: " + dr)
	if cred.Rolename != "" {
		if !rltValue {
			rLog.WithFields(logrus.Fields{
				"role-match":    "role-match: " + result.Result,
				"role-name":     "role-name: " + result.RoleName,
				"mismatch-type": "mismatch-type: " + result.MismatchType,
			}).Warn("found role mismatch (" + result.MismatchType + ")")
		} else {
			rLog.Info("role-match: " + result.Result + " (" + result.RoleName + ")")
		}
	}

	if result.AssertAllowRole {
		rLog.Info("matched: allow")
	}
	if result.AssertDenyRole {
		rLog.Info("matched: deny")
	}

	log.WithFields(logrus.Fields{
		"status": result.StatusCode,
		"alias":  result.Alias,
		"aar":    result.AssertAllowRole,
		"adr":    result.AssertDenyRole,
		"size":   cl,
	}).Debug("")
	return result
}
