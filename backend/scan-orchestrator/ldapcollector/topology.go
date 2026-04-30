package ldapcollector

import (
	"fmt"
	"strings"
)

// CollectTopology returns domain password policy, functional level, and forest info.
func (c *Collector) CollectTopology() (map[string]interface{}, error) {
	// Query the domain root object
	domainEntry, err := c.searchBase(c.baseDN,
		"(objectClass=domain)",
		[]string{
			"maxPwdAge", "minPwdAge", "minPwdLength", "pwdHistoryLength",
			"lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
			"msDS-Behavior-Version", "objectSid", "name", "distinguishedName",
			"nETBIOSName", "tombstoneLifetime",
		},
	)
	if err != nil || domainEntry == nil {
		// Try a subtree search for the domain object
		entries, err2 := c.search(c.baseDN, "(objectClass=domain)", []string{
			"maxPwdAge", "minPwdAge", "minPwdLength", "pwdHistoryLength",
			"lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
			"msDS-Behavior-Version", "objectSid", "name",
		})
		if err2 != nil || len(entries) == 0 {
			return map[string]interface{}{}, nil
		}
		domainEntry = entries[0]
	}

	// Convert Windows tick-based durations (negative 100-ns intervals) to days/minutes
	maxPwdAgeDays := ticksToDays(attrInt64(domainEntry, "maxPwdAge"))
	minPwdAgeDays := ticksToDays(attrInt64(domainEntry, "minPwdAge"))
	lockoutDurMins := ticksToMinutes(attrInt64(domainEntry, "lockoutDuration"))
	observeWindowMins := ticksToMinutes(attrInt64(domainEntry, "lockoutObservationWindow"))

	// Tombstone lifetime lives in the configuration partition
	tombstoneDays := 180 // AD default
	if c.configDN != "" {
		tsEntry, _ := c.searchBase(
			fmt.Sprintf("CN=Directory Service,CN=Windows NT,CN=Services,%s", c.configDN),
			"(objectClass=nTDSService)",
			[]string{"tombstoneLifetime"},
		)
		if tsEntry != nil && attrStr(tsEntry, "tombstoneLifetime") != "" {
			tombstoneDays = attrInt(tsEntry, "tombstoneLifetime")
		}
	}

	// Get NetBIOS name from configuration partition
	netbios := strings.Split(c.domain, ".")[0]
	if c.configDN != "" {
		nbEntries, _ := c.search(
			fmt.Sprintf("CN=Partitions,%s", c.configDN),
			fmt.Sprintf("(&(objectClass=crossRef)(nCName=%s))", c.baseDN),
			[]string{"nETBIOSName"},
		)
		if len(nbEntries) > 0 && attrStr(nbEntries[0], "nETBIOSName") != "" {
			netbios = attrStr(nbEntries[0], "nETBIOSName")
		}
	}

	domain := map[string]interface{}{
		"distinguished_name":    c.baseDN,
		"name":                  c.domain,
		"netbios":               netbios,
		"forest":                c.domain,
		"functional_level":      attrInt(domainEntry, "msDS-Behavior-Version"),
		"domain_sid":            attrSID(domainEntry, "objectSid"),
		"tombstone_lifetime":    tombstoneDays,
		"max_pwd_age":           attrInt64(domainEntry, "maxPwdAge"),
		"min_pwd_age":           attrInt64(domainEntry, "minPwdAge"),
		"min_pwd_length":        attrInt(domainEntry, "minPwdLength"),
		"pwd_history_length":    attrInt(domainEntry, "pwdHistoryLength"),
		"lockout_threshold":     attrInt(domainEntry, "lockoutThreshold"),
		"lockout_duration":      attrInt64(domainEntry, "lockoutDuration"),
		"max_pwd_age_days":      maxPwdAgeDays,
		"min_pwd_age_days":      minPwdAgeDays,
		"lockout_duration_mins": lockoutDurMins,
		"observe_window_mins":   observeWindowMins,
	}

	return map[string]interface{}{
		"domain":  domain,
		"domains": []interface{}{domain},
		"forest": map[string]interface{}{
			"name":             c.domain,
			"root_domain":      c.domain,
			"functional_level": attrInt(domainEntry, "msDS-Behavior-Version"),
			"domains":          []interface{}{domain},
		},
	}, nil
}

// ticksToDays converts negative Windows tick intervals (100-ns) to absolute days.
func ticksToDays(ticks int64) int {
	if ticks >= 0 {
		return 0
	}
	return int(-ticks / 864000000000)
}

// ticksToMinutes converts negative Windows tick intervals to absolute minutes.
func ticksToMinutes(ticks int64) int {
	if ticks >= 0 {
		return 0
	}
	return int(-ticks / 600000000)
}
