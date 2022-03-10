/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd_test

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/ace/test/bdd/pkg/common"
	bddcontext "github.com/trustbloc/ace/test/bdd/pkg/context"
)

const (
	featuresPath    = "features"
	caCertPath      = "fixtures/keys/tls/ec-cacert.pem"
	composeDir      = "./fixtures/"
	composeFilePath = composeDir + "docker-compose.yml"
)

var logger = log.New("ace-bdd")

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all
	tags := "all"

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
		Name:                 "ace test suite",
		TestSuiteInitializer: initializeTestSuite,
		ScenarioInitializer:  initializeScenario,
		Options:              buildOptions(tags, format),
	}.Run()
}

func initializeTestSuite(ctx *godog.TestSuiteContext) {
	var (
		dockerComposeUp   = []string{"docker-compose", "-f", composeFilePath, "up", "--force-recreate", "-d"}
		dockerComposeDown = []string{"docker-compose", "-f", composeFilePath, "down"}
	)

	compose := os.Getenv("DISABLE_COMPOSITION") != "true"

	ctx.BeforeSuite(func() {
		if compose { //nolint:nestif
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
	})

	ctx.AfterSuite(func() {
		if compose {
			logger.Infof("Running %s", strings.Join(dockerComposeDown, " "))

			cmd := exec.Command(dockerComposeDown[0], dockerComposeDown[1:]...) //nolint:gosec
			if out, err := cmd.CombinedOutput(); err != nil {
				logger.Fatalf("%s: %s", err.Error(), string(out))
			}
		}
	})
}

type feature interface {
	// SetContext is called before every scenario is run with a fresh new context.
	SetContext(*bddcontext.BDDContext)
	// RegisterSteps is invoked once to register the steps on the suite.
	RegisterSteps(ctx *godog.ScenarioContext)
}

func initializeScenario(ctx *godog.ScenarioContext) {
	caCertPathVal := caCertPath
	if os.Getenv("DISABLE_CUSTOM_CA") == "true" {
		caCertPathVal = ""
	}

	bddContext, err := bddcontext.NewBDDContext(caCertPathVal)
	if err != nil {
		logger.Fatalf("Failed to create a new BDD context: %s", err.Error())
	}

	features := []feature{
		common.NewSteps(bddContext),
	}

	for _, f := range features {
		f.RegisterSteps(ctx)
	}

	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		for _, f := range features {
			f.SetContext(bddContext)
		}

		return context.Background(), nil
	})
}

func buildOptions(tags, format string) *godog.Options {
	return &godog.Options{
		Tags:          tags,
		Format:        format,
		Paths:         []string{featuresPath},
		Strict:        true,
		StopOnFailure: true,
	}
}
