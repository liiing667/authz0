package scan

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/hahwul/authz0/pkg/models"
)

func checkAssert(res *Response, asserts []models.Assert) bool {
	if res.Truncated {
		return false
	}
	failSizeMargin := 0
	for _, assert := range asserts {
		if assert.Type == "fail-size-margin" {
			failSizeMargin, _ = strconv.Atoi(assert.Value)
		}
	}

	for _, assert := range asserts {
		switch assert.Type {
		case "success-status":
			vArr := strings.Split(assert.Value, ",")
			for _, v := range vArr {
				code, _ := strconv.Atoi(v)
				if res.StatusCode == code {
					return true
				}
			}

		case "fail-status":
			code, _ := strconv.Atoi(assert.Value)
			if res.StatusCode == code {
				return false
			}

		case "fail-regex":
			match, _ := regexp.MatchString(assert.Value, string(res.Body))
			if match {
				return false
			}
		case "fail-size":
			size, _ := strconv.Atoi(assert.Value)
			if res.Size > size-failSizeMargin {
				return false
			}
			if res.Size < size+failSizeMargin {
				return false
			}
		}
	}

	if res.StatusCode == 200 {
		return true
	}
	return false
}
