// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright 2023-2026 Canonical Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package proxy_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/canonical/fetch-service/logger"
	"github.com/canonical/fetch-service/logger/testlogger"
	"github.com/canonical/fetch-service/proxy"
	"github.com/canonical/fetch-service/service/config"
	"github.com/canonical/fetch-service/service/messages"
	"github.com/canonical/fetch-service/session"
	"github.com/canonical/fetch-service/testutils"
	"github.com/canonical/fetch-service/utils"
)

func Test(t *testing.T) { TestingT(t) }

type proxySuite struct{}

var _ = Suite(&proxySuite{})

func (t *proxySuite) SetUpTest(c *C) {
	testlogger.Init(logger.InfoLevel)
}

func (t *proxySuite) TestServerError(c *C) {
	ch := make(chan interface{}, 1)
	spool := c.MkDir()
	p, err := proxy.NewHTTPProxy(5566, spool, testutils.ProxyCert, testutils.ProxyKey, ch)
	c.Assert(err, IsNil)

	err = errors.New("an error")
	p.ForceError(err)
	c.Assert(p.Err(), Equals, err)
}

func (t *proxySuite) TestPassthrough(c *C) {
	oldNoProxy, hadNoProxy := os.LookupEnv("NO_PROXY")
	defer func() {
		if hadNoProxy {
			_ = os.Setenv("NO_PROXY", oldNoProxy)
		} else {
			_ = os.Unsetenv("NO_PROXY")
		}
	}()
	c.Assert(os.Setenv("NO_PROXY", "127.0.0.1"), IsNil)
	cfg := config.GetHTTPProxyConfig()
	defer config.SetHTTPProxyConfig(cfg)
	config.SetHTTPProxyConfig(config.HTTPProxyConfig{Policy: config.Allow})

	ch := make(chan interface{})
	defer close(ch)
	go func() {
		for msg := range ch {
			switch m := msg.(type) {
			case messages.ProxyAuth:
				m.Rch <- session.CheckAuth(m.ID, m.Pw, m.HostIP, m.ClientIP, m.Agent)
			case messages.RequestInspection:
				c.Error("passthrough unexpectedly requested request inspection")
				m.Rch <- errors.New("unexpected request inspection")
			case messages.ResponseInspection:
				c.Error("passthrough unexpectedly requested artifact inspection")
				m.Rch <- errors.New("unexpected artifact inspection")
			}
		}
	}()

	spool := c.MkDir()
	p, err := proxy.NewHTTPProxy(0, spool, testutils.ProxyCert, testutils.ProxyKey, ch)
	c.Assert(err, IsNil)
	px := httptest.NewServer(p.Handler())
	defer px.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Check(r.Method, Equals, "POST")
		c.Check(r.Header.Get("X-Fetch-Session-Id"), Equals, "")
		c.Check(r.Header.Get("Proxy-Authorization"), Equals, "")
		c.Check(r.URL.Query().Get("token"), Equals, "private-query")
		body, err := io.ReadAll(r.Body)
		c.Check(err, IsNil)
		c.Check(string(body), Equals, "request body")
		w.Header().Set("X-Origin", "unchanged")
		_, _ = io.WriteString(w, "uninspected response")
	}))
	defer origin.Close()

	s := session.NewWithPolicy(spool, 0, session.PolicyPassthrough, nil, config.OverrideInspectorsConfig{})
	defer s.Discard()
	proxyURL, err := url.Parse(px.URL)
	c.Assert(err, IsNil)
	proxyURL.User = url.UserPassword(s.ID, s.Token)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Post(origin.URL+"/artifact?token=private-query", "text/plain", strings.NewReader("request body"))
	c.Assert(err, IsNil)
	defer resp.Body.Close()
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
	c.Check(resp.Header.Get("X-Origin"), Equals, "unchanged")
	body, err := io.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	c.Check(string(body), Equals, "uninspected response")
	c.Check(s.Artifacts(), HasLen, 0)
	c.Check(testlogger.Contains(fmt.Sprintf(`passthrough request session=%q client="127.0.0.1" method="POST" url=%q`, s.ID, origin.URL+"/artifact")), Equals, true)
	c.Check(testlogger.Contains("private-query"), Equals, false)

	config.SetHTTPProxyConfig(config.HTTPProxyConfig{Policy: config.Deny})
	denied, err := client.Post(origin.URL+"/artifact?token=private-query", "text/plain", strings.NewReader("request body"))
	c.Assert(err, IsNil)
	denied.Body.Close()
	c.Check(denied.StatusCode, Equals, http.StatusForbidden)

	c.Assert(s.Revoke(s.Token), Equals, true)
	revoked, err := client.Get(origin.URL + "/artifact")
	c.Assert(err, IsNil)
	revoked.Body.Close()
	c.Check(revoked.StatusCode, Equals, http.StatusProxyAuthRequired)
}

// Test file transfer using the proxy.
func (t *proxySuite) TestProxyDownload(c *C) {
	// start the fetch service proxy
	ch := make(chan interface{}, 1)
	spool := c.MkDir()
	p, err := proxy.NewHTTPProxy(5566, spool, testutils.ProxyCert, testutils.ProxyKey, ch)
	c.Assert(err, IsNil)

	err = p.Start()
	c.Assert(err, IsNil)
	defer func() {
		err := p.Stop()
		c.Assert(err, IsNil)
	}()

	time.Sleep(1 * time.Second)

	// create a new session
	s := session.New(spool, 0, true, nil, config.OverrideInspectorsConfig{})
	defer s.Discard()

	// download a test file
	proxyURL := url.URL{
		Scheme: "http",
		User:   url.UserPassword(s.ID, s.Token),
		Host:   "localhost:5566",
	}

	url, err := url.Parse("https://launchpadlibrarian.net/592566337/hello_2.10-2ubuntu4_amd64.deb")
	c.Assert(err, IsNil)

	transport := &http.Transport{
		Proxy:           http.ProxyURL(&proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	go func() {
		req, err := http.NewRequest("GET", url.String(), nil)
		c.Assert(err, IsNil)

		resp, err := client.Do(req)
		c.Assert(err, IsNil)
		c.Assert(resp.StatusCode, Equals, 200)
	}()

	// authorize download
	msg := <-ch
	auth := msg.(messages.ProxyAuth)
	c.Assert(auth.ID, Equals, s.ID)
	c.Assert(auth.Pw, Equals, s.Token)
	auth.Rch <- true

	// run request inspectors
	msg = <-ch
	v := msg.(messages.RequestInspection)
	v.Rch <- nil // no errors

	// artifact downloaded
	msg = <-ch
	u := msg.(messages.ResponseInspection)

	dest := filepath.Join(u.A.AssetDir, fmt.Sprintf("%s.data", u.A.Metadata.Sha256))
	err = os.MkdirAll(filepath.Dir(dest), 0755)
	c.Assert(err, IsNil)

	err = utils.MoveFile(u.A.Tempfile, dest)
	c.Assert(err, IsNil)
	os.Remove(u.A.Tempfile)

	// check downloaded file information
	c.Assert(v.A.MetadataVersion, Equals, "0.3")
	c.Assert(u.A.Metadata.Sha1.String(), Equals, "d8c1f9634007b54c1e9aa3ba3b51395b643933c3")
	c.Assert(u.A.Metadata.Sha256.String(), Equals, "750335248ccc68d07397e2b843d94fd1a164ddeca23892ca8398b5d528cd89eb")
	c.Assert(u.A.Metadata.Size, Equals, int64(26600))

	dl := u.A.CurrentDownload
	c.Assert(dl.StatusCode, Equals, 200)
	c.Assert(dl.URL, Equals, "https://launchpadlibrarian.net:443/592566337/hello_2.10-2ubuntu4_amd64.deb")
	c.Assert(dl.Method, Equals, "GET")
	c.Assert(dl.ContentType, Equals, "application/x-debian-package")
	c.Assert(dl.UserAgent, Equals, "Go-http-client/1.1")
	c.Assert(dl.RequestHeader, DeepEquals, map[string][]string{
		"Accept-Encoding": []string{"gzip"},
		"User-Agent":      []string{"Go-http-client/1.1"},
	})
	c.Assert(dl.ResponseHeader["Content-Length"], DeepEquals, []string{"26600"})
	c.Assert(dl.ResponseHeader["Content-Type"], DeepEquals, []string{"application/x-debian-package"})

	u.Rch <- nil // no errors
}

type copyHeaderTest struct {
	key string   // The header entry key
	val []string // The header entry value
}

var copyHeaderTests = []copyHeaderTest{{
	key: "key",
	val: []string{},
}, {
	key: "key",
	val: []string{"a", "b", "c"},
}}

func (t *proxySuite) TestCopyHeader(c *C) {
	for _, tc := range copyHeaderTests {
		data := map[string][]string{tc.key: tc.val}
		newData := proxy.CopyHTTPHeader(data)
		delete(data, tc.key)
		c.Assert(data[tc.key], IsNil)
		c.Assert(newData, Not(Equals), data)
		c.Assert(newData[tc.key], DeepEquals, tc.val)
		c.Assert(newData[tc.key], Not(Equals), tc.val)
	}
}

type proxyFromEnvironmentTest struct {
	url   string            // The request URL
	env   map[string]string // Proxy-related environment variables
	proxy string            // The expected proxy to use
}

var proxyFromEnvironmentTests = []proxyFromEnvironmentTest{{
	// No proxy variable set
	url:   "http://example.com",
	env:   map[string]string{},
	proxy: "",
}, {
	// Protocols in URL and proxy variable are both HTTP
	url:   "http://example.com",
	env:   map[string]string{"http_proxy": "http://localhost:1234"},
	proxy: "http://localhost:1234",
}, {
	// Protocol in request is HTTP, proxy variable is HTTPS
	url:   "http://example.com",
	env:   map[string]string{"https_proxy": "http://localhost:1234"},
	proxy: "",
}, {
	// Protocol in URL is HTTP, proxy variable is ALL
	url:   "http://example.com",
	env:   map[string]string{"all_proxy": "http://localhost:1234"},
	proxy: "http://localhost:1234",
}, {
	// Protocols in URL and proxy variable are both HTTPS
	url:   "https://example.com",
	env:   map[string]string{"https_proxy": "http://localhost:1234"},
	proxy: "http://localhost:1234",
}, {
	// Protocol in request is HTTPS, proxy variable is HTTP
	url:   "https://example.com",
	env:   map[string]string{"http_proxy": "http://localhost:1234"},
	proxy: "",
}, {
	// Protocol in URL is HTTPS, proxy variable is ALL
	url:   "https://example.com",
	env:   map[string]string{"all_proxy": "http://localhost:1234"},
	proxy: "http://localhost:1234",
}, {
	// Pick the right protocol based on URL
	url:   "https://example.com",
	env:   map[string]string{"http_proxy": "http://localhost:1234", "https_proxy": "http://otherhost:5678"},
	proxy: "http://otherhost:5678",
}, {
	// http_proxy overrides all_proxy
	url:   "http://example.com",
	env:   map[string]string{"http_proxy": "http://localhost:1234", "all_proxy": "http://otherhost:5678"},
	proxy: "http://localhost:1234",
}, {
	// https_proxy overrides all_proxy
	url:   "https://example.com",
	env:   map[string]string{"https_proxy": "http://localhost:1234", "ALL_PROXY": "http://otherhost:5678"},
	proxy: "http://localhost:1234",
}}

func (p *proxySuite) TestProxyFromEnvironment(c *C) {
	for _, tc := range proxyFromEnvironmentTests {
		req, err := http.NewRequest("GET", tc.url, nil)
		c.Assert(err, IsNil)

		for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
			os.Unsetenv(k)
		}

		for _, uppercase := range []bool{false, true} {
			for k, v := range tc.env {
				if uppercase {
					os.Setenv(strings.ToUpper(k), v)
				} else {
					os.Setenv(k, v)
				}
			}

			px, err := proxy.ProxyFromEnvironment(req)
			c.Assert(err, IsNil)
			if tc.proxy == "" {
				c.Assert(px, IsNil)
			} else {
				c.Assert(px.String(), Equals, tc.proxy)
			}
		}
	}
}

type shouldBypassProxyTest struct {
	env    string // The value of the NO_PROXY or no_proxy environment variable
	host   string // The host being verified
	bypass bool   // The expected result
}

var shouldBypassProxyTests = []shouldBypassProxyTest{{
	env:    "",
	host:   "myhost",
	bypass: false,
}, {
	env:    "myhost",
	host:   "myhost",
	bypass: true,
}, {
	env:    "myhost",
	host:   "MyHost",
	bypass: true,
}, {
	env:    "myhost",
	host:   "myhost.example.com",
	bypass: false,
}, {
	env:    "*.example.com",
	host:   "myhost.example.com",
	bypass: true,
}, {
	env:    "cat.com, dog.com",
	host:   "corndog.com",
	bypass: false,
}, {
	env:    "cat.com, *dog.com",
	host:   "corndog.com",
	bypass: true,
}, {
	env:    "cat.com, *.d[oi]g.com",
	host:   "myhost.dig.com",
	bypass: true,
}, {
	env:    "cat.com, *.d[oig.com",
	host:   "myhost.dig.com",
	bypass: false,
}}

func (t *proxySuite) TestShouldBypassProxy(c *C) {
	for _, tc := range shouldBypassProxyTests {
		for _, noProxyVar := range []string{"no_proxy", "NO_PROXY"} {
			os.Unsetenv("no_proxy")
			os.Unsetenv("NO_PROXY")

			if tc.env != "" {
				os.Setenv(noProxyVar, tc.env)
			}

			res := proxy.ShouldBypassProxy(tc.host)
			c.Check(res, Equals, tc.bypass, Commentf("var: %s, test case: %+v", noProxyVar, tc))
		}
	}

	os.Unsetenv("no_proxy")
	os.Unsetenv("NO_PROXY")
}

func (t *proxySuite) TestGetEnvAny(c *C) {
	os.Setenv("VAR1", "")
	os.Setenv("VAR2", "value2")
	os.Setenv("VAR3", "value2")

	value := proxy.GetenvAny("VAR1", "VAR2", "VAR3")
	c.Assert(value, Equals, "value2")

	os.Unsetenv("VAR1")
	os.Unsetenv("VAR2")
	os.Unsetenv("VAR3")

	value = proxy.GetenvAny("VAR1", "VAR2", "VAR3")
	c.Assert(value, Equals, "")
}
