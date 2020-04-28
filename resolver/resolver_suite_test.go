package resolver_test

import (
	"github.com/sirupsen/logrus"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestResolver(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resolver Suite")
}
