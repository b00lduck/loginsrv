package httpupstream

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Auth is the httpupstream authenticater
type Auth struct {
	upstream   *url.URL
	skipverify bool
	timeout    time.Duration
}

// NewAuth creates an httpupstream authenticater
func NewAuth(upstream *url.URL, timeout time.Duration, skipverify bool) (*Auth, error) {
	a := &Auth{
		upstream:   upstream,
		skipverify: skipverify,
		timeout:    timeout,
	}

	return a, nil
}

// Authenticate the user
func (a *Auth) Authenticate(username, password string) (bool, []string, error) {
	c := &http.Client{
		Timeout: a.timeout,
	}

	if a.upstream.Scheme == "https" && a.skipverify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest("GET", a.upstream.String(), nil)
	if err != nil {
		return false, []string{}, err
	}

	req.SetBasicAuth(username, password)

	resp, err := c.Do(req)
	if err != nil {
		return false, []string{}, err
	}

	if resp.StatusCode != 200 {
		return false, []string{}, nil
	}

	groups := a.extractgroupsFromHeader(resp, "Auth-Roles")
	return true, groups, nil
}

func (a *Auth) extractgroupsFromHeader(resp *http.Response, headerName string) []string {
	groupsString := resp.Header.Get(headerName)
	if len(groupsString) == 0 {
		return []string{}
	}

	groupsSlice := strings.Split(groupsString, ",")

	ret := []string{}
	for _, role := range groupsSlice {
		ret = append(ret, strings.TrimSpace(role))
	}
	return ret
}
