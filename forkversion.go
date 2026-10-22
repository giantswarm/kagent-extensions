package main

import (
	_ "embed"
	"fmt"
	"strings"
)

// forkVersionFile names the fork release this binary is built on and the
// commit of its tag, which go.mod's replace pins (TestForkVersionMatchesGoMod).
//
//go:embed FORK_VERSION
var forkVersionFile string

// imageTagEnv is the release of the kagent chart the controller runs under: the
// chart's controller ConfigMap sets it to the release it was published as.
const imageTagEnv = "IMAGE_TAG"

type forkRelease struct {
	version string
	commit  string
}

func parseForkVersion(content string) (forkRelease, error) {
	fields := strings.Fields(content)
	if len(fields) != 2 {
		return forkRelease{}, fmt.Errorf("FORK_VERSION is %q, want \"<release> <commit>\"", strings.TrimSpace(content))
	}
	return forkRelease{version: strings.TrimPrefix(fields[0], "v"), commit: fields[1]}, nil
}

// checkChartRelease refuses to run under a kagent chart of another release than
// the fork release the binary embeds: the chart's Deployment, CRDs and
// configuration are written for its own controller, and the controller
// migrates the database at start. Build metadata (helm-controller's
// +<digest>) and a leading v are ignored.
func checkChartRelease(fork forkRelease, imageTag string, allowSkew bool) error {
	chart := strings.TrimPrefix(imageTag, "v")
	chart, _, _ = strings.Cut(chart, "+")
	switch {
	case allowSkew:
		return nil
	case chart == "":
		return fmt.Errorf("%s is not set, so the kagent chart's release is unknown; this binary is built on fork release %s (--allow-version-skew runs it anyway)", imageTagEnv, fork.version)
	case chart != fork.version:
		return fmt.Errorf("the kagent chart is release %s but this binary is built on fork release %s: run the kagent-extensions image of release %s (--allow-version-skew runs it anyway)", chart, fork.version, chart)
	default:
		return nil
	}
}
