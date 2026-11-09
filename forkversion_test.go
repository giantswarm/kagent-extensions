package main

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

const forkModule = "github.com/kagent-dev/kagent/go"

const release = "1.24.6"

func TestForkVersionMatchesGoMod(t *testing.T) {
	fork, err := parseForkVersion(forkVersionFile)
	require.NoError(t, err)
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)
	file, err := modfile.Parse("go.mod", content, nil)
	require.NoError(t, err)
	var pinned string
	for _, replace := range file.Replace {
		if replace.Old.Path == forkModule {
			pinned = replace.New.Version
		}
	}
	require.NotEmpty(t, pinned, "go.mod replaces %s", forkModule)
	revision, err := module.PseudoVersionRev(pinned)
	require.NoError(t, err)
	require.Equal(t, revision, fork.commit, "FORK_VERSION names the commit go.mod pins")
}

// e2eRelease is the fork release the E2E workflow builds the checkout against.
var e2eRelease = regexp.MustCompile(`(?m)^\s*KAGENT_RELEASE:\s*(\S+)\s*$`)

// The E2E workflow must not test the checkout against an older fork tree
// than the one it is built on. Until FORK_VERSION is on the 1.31.1 line,
// the two cannot be equal: older releases lack the cross-creator delete review.
func TestE2EReleaseIsNotOlderThanForkVersion(t *testing.T) {
	fork, err := parseForkVersion(forkVersionFile)
	require.NoError(t, err)
	workflow, err := os.ReadFile(".github/workflows/e2e.yaml")
	require.NoError(t, err)
	match := e2eRelease.FindSubmatch(workflow)
	require.NotNil(t, match, "e2e.yaml sets KAGENT_RELEASE")
	e2e, forkVersion := "v"+string(match[1]), "v"+fork.version
	require.True(t, semver.IsValid(e2e), "KAGENT_RELEASE %s is a semantic version", match[1])
	require.True(t, semver.IsValid(forkVersion), "FORK_VERSION %s is a semantic version", fork.version)
	require.GreaterOrEqual(t, semver.Compare(e2e, forkVersion), 0, "KAGENT_RELEASE %s is older than FORK_VERSION %s", match[1], fork.version)
}

func TestParseForkVersion(t *testing.T) {
	fork, err := parseForkVersion("v1.24.6 e5785cca562a\n")
	require.NoError(t, err)
	require.Equal(t, forkRelease{version: release, commit: "e5785cca562a"}, fork)
	for _, invalid := range []string{"", release, "1.24.6 e5785cca562a extra"} {
		_, err := parseForkVersion(invalid)
		require.Error(t, err, invalid)
	}
}

func TestCheckChartRelease(t *testing.T) {
	fork := forkRelease{version: release, commit: "e5785cca562a"}
	for _, imageTag := range []string{release, "v1.24.6", "1.24.6+843b51bb7798"} {
		require.NoError(t, checkChartRelease(fork, imageTag, false), imageTag)
	}
	for imageTag, reason := range map[string]string{
		"":                   "IMAGE_TAG is not set",
		"1.24.7":             "the kagent chart is release 1.24.7 but this binary is built on fork release 1.24.6",
		"1.24.6-rc.1":        "the kagent chart is release 1.24.6-rc.1",
		"1.24.7-r588f3d76t1": "the kagent chart is release 1.24.7-r588f3d76t1",
	} {
		require.ErrorContains(t, checkChartRelease(fork, imageTag, false), reason, imageTag)
		require.NoError(t, checkChartRelease(fork, imageTag, true), "allowed skew: %s", imageTag)
	}
}
