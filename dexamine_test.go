package main

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBasic(t *testing.T) {

	// Avoid using /proc/self/exe if this is a temporary executable,
	// since "go test" passes -w to the linker.
	exe := "/proc/self/exe"
	linked, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s) failed: %v", exe, err)
	}
	if strings.HasPrefix(linked, "/tmp") && strings.HasSuffix(linked, "dwdisplayfcn.test") {
		// Create tempdir
		dir, err := ioutil.TempDir("", "TestBasicTmpDir")
		if err != nil {
			t.Fatalf("could not create directory: %v", err)
		}
		defer os.RemoveAll(dir)

		// Do a build of . into <tmpdir>/out.exe
		exe = filepath.Join(dir, "out.exe")
		gotoolpath := filepath.Join(runtime.GOROOT(), "bin", "go")
		cmd := exec.Command(gotoolpath, "build", "-o", exe, ".")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Logf("build: %s\n", b)
			t.Fatalf("build error: %v", err)
		}
	}

	// Now examine the result.
	res := examineFile(exe, "main.main")
	if !res {
		t.Errorf("examineFile returned false")
	}
}
