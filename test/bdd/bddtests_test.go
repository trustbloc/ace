/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd_test

import (
	"crypto/tls"
	"flag"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	tlsutil "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/ace/test/bdd/pkg/common"
	"github.com/trustbloc/ace/test/bdd/pkg/comparator"
	"github.com/trustbloc/ace/test/bdd/pkg/csh"
	"github.com/trustbloc/ace/test/bdd/pkg/gatekeeper"
	"github.com/trustbloc/ace/test/bdd/pkg/vault"
)

const (
	caCertPath      = "fixtures/keys/tls/ec-cacert.pem"
	composeDir      = "./fixtures/"
	composeFilePath = composeDir + "docker-compose.yml"
)

var (
	logger    = log.New("ace-bdd")
	tlsConfig *tls.Config //nolint:gochecknoglobals
)

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all but excluding those marked with @wip
	tags := "@all && ~@wip"

	if os.Getenv("TAGS") != "" {
		tags = os.Getenv("TAGS")
	}

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" { //nolint:goconst
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	status := runBDDTests(tags, format)

	os.Exit(status)
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

func runBDDTests(tags, format string) int {
	return godog.TestSuite{
		Name:                 "ACE test suite",
		TestSuiteInitializer: initializeTestSuite,
		ScenarioInitializer:  initializeScenario,
		Options:              buildOptions(tags, format),
	}.Run()
}

func initializeTestSuite(ctx *godog.TestSuiteContext) {
	if os.Getenv("DISABLE_CUSTOM_CA") != "true" {
		rootCAs, err := tlsutil.GetCertPool(false, []string{caCertPath})
		if err != nil {
			logger.Fatalf("Failed to create root CA: %s", err.Error())

			return
		}

		tlsConfig = &tls.Config{
			RootCAs: rootCAs, MinVersion: tls.VersionTLS12,
		}
	}

	if os.Getenv("DISABLE_COMPOSITION") == "true" {
		return
	}

	ctx.BeforeSuite(beforeSuiteHook)
	ctx.AfterSuite(afterSuiteHook)
}

func beforeSuiteHook() {
	dockerComposeUp := []string{"docker-compose", "-f", composeFilePath, "up", "--force-recreate", "-d"}

	logger.Infof("Running %s", strings.Join(dockerComposeUp, " "))

	cmd := exec.Command(dockerComposeUp[0], dockerComposeUp[1:]...) //nolint:gosec
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Fatalf("%s: %s", err.Error(), string(out))
	}

	testSleep := 10

	if os.Getenv("TEST_SLEEP") != "" {
		s, err := strconv.Atoi(os.Getenv("TEST_SLEEP"))
		if err != nil {
			logger.Errorf("invalid 'TEST_SLEEP' value: %w", err)
		} else {
			testSleep = s
		}
	}

	logger.Infof("*** testSleep=%d\n\n", testSleep)
	time.Sleep(time.Second * time.Duration(testSleep))
}

func afterSuiteHook() {
	dockerComposeDown := []string{"docker-compose", "-f", composeFilePath, "down"}

	logger.Infof("Running %s", strings.Join(dockerComposeDown, " "))

	cmd := exec.Command(dockerComposeDown[0], dockerComposeDown[1:]...) //nolint:gosec
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Fatalf("%s: %s", err.Error(), string(out))
	}
}

type feature interface {
	// RegisterSteps registers scenario steps.
	RegisterSteps(sc *godog.ScenarioContext)
}

func initializeScenario(sc *godog.ScenarioContext) {
	commonSteps, err := common.NewSteps(tlsConfig)
	if err != nil {
		panic(err)
	}

	commonSteps.RegisterSteps(sc)

	vaultSteps, err := vault.NewSteps(tlsConfig)
	if err != nil {
		panic(err)
	}

	comparatorSteps, err := comparator.NewSteps(tlsConfig)
	if err != nil {
		panic(err)
	}

	features := []feature{
		gatekeeper.NewSteps(commonSteps),
		vaultSteps,
		comparatorSteps,
		csh.NewSteps(tlsConfig),
	}

	for _, f := range features {
		f.RegisterSteps(sc)
	}
}

func buildOptions(tags, format string) *godog.Options {
	return &godog.Options{
		Tags:          tags,
		Format:        format,
		Strict:        true,
		StopOnFailure: true,
	}
}
