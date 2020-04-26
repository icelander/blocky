package resolver

import (
	"blocky/api"
	"blocky/config"
	"blocky/helpertest"
	"blocky/util"
	"encoding/json"
	"github.com/go-chi/chi"
	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"net/http"
	"os"
	"time"
)

var _ = Describe("BlockingResolver", func() {
	var (
		sut       *BlockingResolver
		sutConfig config.BlockingConfig
		m         *resolverMock

		err  error
		resp *Response

		group1File, group2File, defaultGroupFile *os.File

		expectedReturnCode int
	)

	BeforeEach(func() {
		group1File = helpertest.TempFile("DOMAIN1.com")
		group2File = helpertest.TempFile("blocked2.com")
		defaultGroupFile = helpertest.TempFile("blocked3.com\n123.145.123.145\n2001:db8:85a3:08d3::370:7344\nbadcnamedomain.com")

		expectedReturnCode = dns.RcodeSuccess

		sutConfig = config.BlockingConfig{}

		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
	})

	JustBeforeEach(func() {
		sut = NewBlockingResolver(chi.NewRouter(), sutConfig).(*BlockingResolver)
		sut.Next(m)
	})

	AfterEach(func() {
		group1File.Close()
		group2File.Close()
		defaultGroupFile.Close()
	})

	AfterEach(func() {
		Expect(err).ShouldNot(HaveOccurred())
		Expect(resp.Res.Rcode).Should(Equal(expectedReturnCode))
	})

	Describe("Blocking requests", func() {

		BeforeEach(func() {
			sutConfig = config.BlockingConfig{
				BlackLists: map[string][]string{
					"gr1":          {group1File.Name()},
					"gr2":          {group2File.Name()},
					"defaultGroup": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"client1":        {"gr1"},
					"192.168.178.55": {"gr1"},
					"altName":        {"gr2"},
					"default":        {"defaultGroup"},
				},
				BlockType: "ZeroIP",
			}
		})
		AfterEach(func() {
			Expect(resp.RType).Should(Equal(BLOCKED))
		})

		When("client name is defined in client groups block", func() {
			It("should block the A query if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "client1"))

				Expect(resp.Res.Answer[0].String()).Should(Equal("domain1.com.\t21600\tIN\tA\t0.0.0.0"))
			})
			It("should block the AAAA query if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeAAAA, "1.2.1.2", "client1"))

				Expect(resp.Res.Answer[0].String()).Should(Equal("domain1.com.\t21600\tIN\tAAAA\t::"))
			})
		})

		When("Client ip is defined in client groups block", func() {
			It("should block the query if domain is on the black list", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "192.168.178.55", "unknown"))

				Expect(resp.Res.Answer[0].String()).Should(Equal("domain1.com.\t21600\tIN\tA\t0.0.0.0"))
			})
		})

		When("Client has multiple names and for each name a client group block definition exists", func() {
			It("should block query if domain is in one group", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "client1", "altName"))

				Expect(resp.Reason).Should(Equal("BLOCKED (gr1)"))
				Expect(resp.Res.Answer[0].String()).Should(Equal("domain1.com.\t21600\tIN\tA\t0.0.0.0"))
			})
			It("should block query if domain is in another group too", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked2.com.", dns.TypeA, "1.2.1.2", "client1", "altName"))

				Expect(resp.Reason).Should(Equal("BLOCKED (gr2)"))
				Expect(resp.Res.Answer[0].String()).Should(Equal("blocked2.com.\t21600\tIN\tA\t0.0.0.0"))
			})
		})

		When("Default group is defined", func() {
			It("should block domains from default group for each client", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))

				Expect(resp.Reason).Should(Equal("BLOCKED (defaultGroup)"))
				Expect(resp.Res.Answer[0].String()).Should(Equal("blocked3.com.\t21600\tIN\tA\t0.0.0.0"))
			})
		})

		When("BlockType is NxDomain", func() {
			JustBeforeEach(func() {
				sut.blockType = NxDomain
				expectedReturnCode = dns.RcodeNameError
			})

			It("should return NXDOMAIN if query is blocked", func() {
				resp, err = sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))

				Expect(resp.Reason).Should(Equal("BLOCKED (defaultGroup)"))
				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeNameError))
			})
		})

		When("Blacklist contains IP", func() {
			When("IP4", func() {
				BeforeEach(func() {
					// return defined IP as response
					m = &resolverMock{}
					mockResp, _ := util.NewMsgWithAnswer("example.com. 300 IN A 123.145.123.145")

					m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
				})
				It("should block query, if lookup result contains blacklisted IP", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(resp.Reason).Should(Equal("BLOCKED IP (defaultGroup)"))
					Expect(resp.Res.Answer[0].String()).Should(Equal("example.com.\t21600\tIN\tA\t0.0.0.0"))
				})
			})
			When("IP6", func() {
				BeforeEach(func() {
					// return defined IP as response
					m = &resolverMock{}
					mockResp, _ := util.NewMsgWithAnswer("example.com. 300 IN AAAA 2001:0db8:85a3:08d3::0370:7344")

					m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
				})
				It("should block query, if lookup result contains blacklisted IP", func() {
					resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeAAAA, "1.2.1.2", "unknown"))
					Expect(resp.Reason).Should(Equal("BLOCKED IP (defaultGroup)"))
					Expect(resp.Res.Answer[0].String()).Should(Equal("example.com.\t21600\tIN\tAAAA\t::"))
				})
			})
		})

		When("blacklist contains domain which is CNAME in response", func() {
			BeforeEach(func() {
				// reconfigure mock, to return CNAMEs
				m = &resolverMock{}
				rr1, _ := dns.NewRR("example.com 300 IN CNAME domain.com")
				rr2, _ := dns.NewRR("domain.com 300 IN CNAME badcnamedomain.com")
				rr3, _ := dns.NewRR("badcnamedomain.com 300 IN A 125.125.125.125")
				mockResp := new(dns.Msg)
				mockResp.Answer = []dns.RR{rr1, rr2, rr3}

				m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
			})
			It("should block the query, if response contains a CNAME with domain on a blacklist", func() {
				resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))
				Expect(resp.Reason).Should(Equal("BLOCKED CNAME (defaultGroup)"))
				Expect(resp.Res.Answer[0].String()).Should(Equal("example.com.\t21600\tIN\tA\t0.0.0.0"))
			})
		})
	})

	Describe("Whitelisting", func() {
		When("Requested domain is on black and white list", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{"gr1": {group1File.Name()}},
					WhiteLists: map[string][]string{"gr1": {group1File.Name()}},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
			})
			It("Should not be blocked", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
		})

		When("Only whitelist is defined", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					WhiteLists: map[string][]string{"gr1": {group1File.Name()}},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
			})
			It("should block everything else except domains on the white list", func() {
				By("querying domain on the whitelist", func() {
					resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeA, "1.2.1.2", "unknown"))

					// was delegated to next resolver
					m.AssertExpectations(GinkgoT())
				})

				By("querying another domain, which is not on the whitelist", func() {
					resp, err = sut.Resolve(newRequestWithClient("google.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(m.Calls).Should(HaveLen(1))
					Expect(resp.Reason).Should(Equal("BLOCKED (WHITELIST ONLY)"))
				})
			})
		})

		When("IP address is on black and white list", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{"gr1": {group1File.Name()}},
					WhiteLists: map[string][]string{"gr1": {defaultGroupFile.Name()}},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
				m := &resolverMock{}
				mockResp, _ := util.NewMsgWithAnswer("example.com. 300 IN A 123.145.123.145")

				m.On("Resolve", mock.Anything).Return(&Response{Res: mockResp}, nil)
			})
			It("should not block if DNS answer contains IP from the white list", func() {
				resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))

				// was delegated to next resolver
				m.AssertExpectations(GinkgoT())
			})
		})
	})

	Describe("Delegate request to next resolver", func() {
		BeforeEach(func() {
			sutConfig = config.BlockingConfig{
				BlackLists: map[string][]string{"gr1": {group1File.Name()}},
				ClientGroupsBlock: map[string][]string{
					"default": {"gr1"},
				},
			}
		})
		AfterEach(func() {
			// was delegated to next resolver
			m.AssertExpectations(GinkgoT())

			Expect(resp.RType).Should(Equal(RESOLVED))
		})
		When("domain is not on the black list", func() {
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))
			})
		})
		When("request is not A or AAAA", func() {
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequestWithClient("domain1.com.", dns.TypeMX, "1.2.1.2", "unknown"))
			})
		})
		When("no lists defined", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{}
			})
			It("should delegate to next resolver", func() {
				resp, err = sut.Resolve(newRequestWithClient("example.com.", dns.TypeA, "1.2.1.2", "unknown"))
			})
		})
	})

	Describe("Control status via API", func() {
		BeforeEach(func() {
			sutConfig = config.BlockingConfig{
				BlackLists: map[string][]string{
					"defaultGroup": {defaultGroupFile.Name()},
				},
				ClientGroupsBlock: map[string][]string{
					"default": {"defaultGroup"},
				},
				BlockType: "ZeroIP",
			}
		})
		When("Disable blocking is called", func() {
			It("no query should be blocked", func() {
				By("Perform query to ensure that the blocking status is active", func() {
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).ShouldNot(HaveOccurred())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})

				By("Calling Rest API to deactivate", func() {
					httpCode, _ := helpertest.DoGetRequest("/api/blocking/disable", sut.apiBlockingDisable)
					Expect(httpCode).Should(Equal(http.StatusOK))
				})

				By("perform the same query again", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).ShouldNot(HaveOccurred())
					Expect(resp.RType).Should(Equal(RESOLVED))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
				})

			})
		})

		When("Disable blocking is called with a wrong parameter", func() {
			It("Should return http bad request as return code", func() {
				httpCode, _ := helpertest.DoGetRequest("/api/blocking/disable?duration=xyz", sut.apiBlockingDisable)

				Expect(httpCode).Should(Equal(http.StatusBadRequest))
			})
		})

		When("Disable blocking is called with a duration parameter", func() {
			It("No query should be blocked only for passed amount of time", func() {
				By("Perform query to ensure that the blocking status is active", func() {
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).ShouldNot(HaveOccurred())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})

				By("Calling Rest API to deactivate blocking for 0.5 sec", func() {
					httpCode, _ := helpertest.DoGetRequest("/api/blocking/disable?duration=500ms", sut.apiBlockingDisable)
					Expect(httpCode).Should(Equal(http.StatusOK))
				})

				By("perform the same query again to ensure that this query will not be blocked", func() {
					// now is blocking disabled, query the url again
					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).ShouldNot(HaveOccurred())
					Expect(resp.RType).Should(Equal(RESOLVED))

					m.AssertExpectations(GinkgoT())
					m.AssertNumberOfCalls(GinkgoT(), "Resolve", 1)
				})

				By("Wait 1 sec and perform the same query again, should be blocked now", func() {
					// wait 1 sec
					time.Sleep(time.Second)

					resp, err := sut.Resolve(newRequestWithClient("blocked3.com.", dns.TypeA, "1.2.1.2", "unknown"))
					Expect(err).ShouldNot(HaveOccurred())
					Expect(resp.RType).Should(Equal(BLOCKED))
				})
			})
		})

		When("Blocking status is called", func() {
			It("should return correct status", func() {
				By("enable blocking via API", func() {
					httpCode, _ := helpertest.DoGetRequest("/api/blocking/enable", sut.apiBlockingEnable)
					Expect(httpCode).Should(Equal(http.StatusOK))
				})

				By("Query blocking status via API should return 'enabled'", func() {
					httpCode, body := helpertest.DoGetRequest("/api/blocking/status", sut.apiBlockingStatus)
					Expect(httpCode).Should(Equal(http.StatusOK))
					var result api.BlockingStatus
					err := json.NewDecoder(body).Decode(&result)
					Expect(err).ShouldNot(HaveOccurred())

					Expect(result.Enabled).Should(BeTrue())
				})

				By("disable blocking via API", func() {
					httpCode, _ := helpertest.DoGetRequest("/api/blocking/disable?duration=500ms", sut.apiBlockingDisable)
					Expect(httpCode).Should(Equal(http.StatusOK))
				})

				By("Query blocking status via API again should return 'disabled'", func() {
					httpCode, body := helpertest.DoGetRequest("/api/blocking/status", sut.apiBlockingStatus)
					Expect(httpCode).Should(Equal(http.StatusOK))

					var result api.BlockingStatus
					err := json.NewDecoder(body).Decode(&result)
					Expect(err).ShouldNot(HaveOccurred())

					Expect(result.Enabled).Should(BeFalse())
				})
			})
		})
	})

	Describe("Configuration output", func() {
		When("resolver is enabled", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{
					BlackLists: map[string][]string{"gr1": {group1File.Name()}},
					ClientGroupsBlock: map[string][]string{
						"default": {"gr1"},
					},
				}
			})
			It("should return configuration", func() {
				c := sut.Configuration()
				Expect(len(c) > 1).Should(BeTrue())
			})
		})

		When("resolver is disabled", func() {
			BeforeEach(func() {
				sutConfig = config.BlockingConfig{}
			})
		})
		It("should return 'disabled''", func() {
			c := sut.Configuration()
			Expect(c).Should(HaveLen(1))
			Expect(c).Should(Equal([]string{"deactivated"}))
		})
	})

	Describe("Create resolver with wrong parameter", func() {
		When("Wrong blockType is used", func() {
			var fatal bool
			It("should end with fatal exit", func() {
				defer func() { logrus.StandardLogger().ExitFunc = nil }()

				logrus.StandardLogger().ExitFunc = func(int) { fatal = true }

				_ = NewBlockingResolver(chi.NewRouter(), config.BlockingConfig{
					BlockType: "wrong",
				})

				Expect(fatal).Should(BeTrue())
			})
		})
	})
})
