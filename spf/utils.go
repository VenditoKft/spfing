package spf

import (
	"fmt"
	"regexp"

	"log"
)

const (
	aMXRegex     = `^([+-~]){0,1}(a|mx)(?::([a-zA-Z0-9-._]+)){0,1}(?:\/(3[0-2]|[12][0-9]|[1-9])){0,1}(?:\/(12[0-8]|1[01][0-9]|[1-9][0-9]|[1-9])){0,1}$`
	aRegex       = `^([+-~]){0,1}(a)(?::([a-zA-Z0-9-._]+)){0,1}(?:\/(3[0-2]|[12][0-9]|[1-9])){0,1}(?:\/(12[0-8]|1[01][0-9]|[1-9][0-9]|[1-9])){0,1}$`
	mxRegex      = `^([+-~]){0,1}(mx)(?::([a-zA-Z0-9-._]+)){0,1}(?:\/(3[0-2]|[12][0-9]|[1-9])){0,1}(?:\/(12[0-8]|1[01][0-9]|[1-9][0-9]|[1-9])){0,1}$`
	includeRegex = `^([+-~]){0,1}include(?::([a-zA-Z0-9-._]+)){0,1}$`
	ipRegex      = `^([+-~]){0,1}ip([46])(?::([0-9.:a-f]*))(?:\/(3[0-2]|[12][0-9]|[1-9])){0,1}(?:\/(12[0-8]|1[01][0-9]|[1-9][0-9]|[1-9])){0,1}$`
	allRegex     = `^([+-~])all$`
)

func IsAMechanism(mechanism string) bool {
	match, err := regexp.MatchString(aRegex, mechanism)
	if err != nil {
		log.Printf("regex error %s", err)
		return false
	}
	return match
}

func IsIncludeMechanism(mechanism string) bool {
	match, err := regexp.MatchString(includeRegex, mechanism)
	if err != nil {
		log.Printf("regex error %s", err)
		return false
	}
	return match
}

func isMXMechanism(mechanism string) bool {
	match, err := regexp.MatchString(mxRegex, mechanism)
	if err != nil {
		log.Printf("regex error %s", err)
		return false
	}
	return match
}

func isALLMechanism(mechanism string) bool {
	match, err := regexp.MatchString(allRegex, mechanism)
	if err != nil {
		log.Printf("regex error %s", err)
		return false
	}
	return match
}

func isIPMechanism(mechanism string) bool {
	match, err := regexp.MatchString(ipRegex, mechanism)
	if err != nil {
		log.Printf("regex error %s", err)
		return false
	}
	return match
}

func matchQualifier(q string) (qualifier Qualifier) {
	switch q {
	case "~":
		qualifier = Softfail
	case "-":
		qualifier = Fail
	case "?":
		qualifier = Neutral
	default:
		qualifier = Pass
	}
	return
}

func matchAMX(part string) (qualifier string, mechanism string, domain string, cidr4 string, cidr6 string, errRtn error) {
	re, err := regexp.Compile(aMXRegex)
	if err != nil {
		log.Printf("failed to compile regex %s", err)
	}
	if !re.MatchString(part) {
		errRtn = fmt.Errorf("%w - got %s", WrongFormat, part)
		return
	}
	components := re.FindStringSubmatch(part)
	if len(components) != 6 {
		errRtn = fmt.Errorf("%w - got %s", WrongFormat, part)
		return
	}
	qualifier = components[1]
	if qualifier == "" {
		qualifier = "+"
	}
	mechanism = components[2]
	domain = components[3]
	cidr4 = components[4]
	cidr6 = components[5]
	return
}

func matchInclude(part string) (qualifier string, domain string, errRtn error) {
	re, err := regexp.Compile(includeRegex)
	if err != nil {
		log.Printf("failed to compile regex %s", err)
	}
	if !re.MatchString(part) {
		errRtn = fmt.Errorf("%w - got %s", WrongFormat, part)
		return
	}

	components := re.FindStringSubmatch(part)
	if len(components) != 3 {
		errRtn = fmt.Errorf("%w - got %s", WrongFormat, part)
		return
	}
	qualifier = components[1]
	domain = components[2]
	return
}

func matchIP(part string) (qualifier string, version string, ip string, cidr string, errRtn error) {
	re, err := regexp.Compile(ipRegex)
	if err != nil {
		log.Printf("failed to compile regex %s", err)
	}
	if !re.MatchString(part) {
		errRtn = fmt.Errorf("%w - got %s", WrongFormat, part)
		return
	}

	components := re.FindStringSubmatch(part)
	if len(components) != 6 {
		errRtn = fmt.Errorf("%w - got %s", WrongFormat, part)
		return
	}
	qualifier = components[1]
	version = components[2]
	ip = components[3]
	if version == "6" {
		cidr = components[5]
	}
	if version == "4" {
		cidr = components[4]
	}
	return
}
