package examine_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thanm/dwdisplayfcn/examine"
)

func TestBasic(t *testing.T) {

	dir := t.TempDir()

	// Do a build of abc.go into <tmpdir>/out.exe
	exe := filepath.Join(dir, "out.exe")
	gotoolpath := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(gotoolpath, "build", "-o", exe, "testdata/abc.go")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Logf("build: %s\n", b)
		t.Fatalf("build error: %v", err)
	}

	// Now examine the result.
	println("=-= exe is ", exe)
	res := examine.ExamineFile(exe, "main.ABC")
	if !res {
		t.Errorf("examineFile returned false")
	}
	res = examine.ExamineFile(exe, "main.NotThere")
	if res {
		t.Errorf("examineFile returned true for nonexistent func")
	}
}
