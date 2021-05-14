// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package examine

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/proc"
	"github.com/thanm/dwarf-check/dwexaminer"
)

var VerbLevel int

type finfo struct {
	name     string
	dwOffset dwarf.Offset
	dwLowPC  uint64
	sValue   uint64
	sSize    uint64
	valid    bool
	params   []param
}

type examination struct {
	warnings []string
	status   bool
}

type param struct {
	name  string
	entry dwarf.Entry
}

func warn(s string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, s, a...)
	fmt.Fprintf(os.Stderr, "\n")
}

func verb(vlevel int, s string, a ...interface{}) {
	if VerbLevel >= vlevel {
		fmt.Printf(s, a...)
		fmt.Printf("\n")
	}
}

func ExamineFile(loadmodule string, fcn string) bool {
	fi := locateFuncDetails(loadmodule, fcn)
	if !fi.valid {
		return false
	}
	asmLines := genasmdump(loadmodule, fcn, fi)
	if len(asmLines) == 0 {
		warn("empty asm dump, aborting")
		return false
	}
	bi := collectParams(loadmodule, &fi)
	if bi == nil {
		return false
	}
	emitAnnotatedDump(asmLines, fi, bi)
	return true
}

//  47dbe0:       cmp    0x10(%r14),%rsp
//  47dbe4:       jbe    47dc3c <main.main+0x5c>
//  47dbe6:       sub    $0x40,%rsp

func pstring(pcs []op.Piece) string {
	r := "{"
	for k, p := range pcs {
		r += fmt.Sprintf(" [%d: S=%d", k, p.Size)
		if p.IsRegister {
			r += fmt.Sprintf(" reg=%d]", p.RegNum)
		} else {
			r += fmt.Sprintf(" addr=0x%x]", p.Addr)
		}
	}
	return r
}

func emitAnnotatedDump(asmLines []string, fi finfo, bi *proc.BinaryInfo) {
	const _cfa = 0x1000
	instre := regexp.MustCompile(`^\s+([0-9a-f]+)\:\s+\S+`)
	pstate := make([]string, len(fi.params))
	for _, line := range asmLines {
		fmt.Printf("%s\n", line)
		matched := instre.FindStringSubmatch(line)
		if matched == nil {
			continue
		}
		hexaddr := matched[1]
		pc, err := strconv.ParseUint(hexaddr, 16, 64)
		if err != nil {
			continue
		}
		for k, p := range fi.params {
			_, pieces, _, err := bi.Location(&p.entry, dwarf.AttrLocation, pc, op.DwarfRegisters{CFA: _cfa, FrameBase: _cfa})
			if err != nil {
				warn("bad return from bi.Location at pc 0x%x: %s",
					pc, err)
				return
			}
			pdump := pstring(pieces)
			if pdump != pstate[k] {
				fmt.Printf(" ^ %q now in: %s\n", p.name, pdump)
				pstate[k] = pdump
			}
		}
	}
}

func genasmdump(loadmodule string, fcn string, fi finfo) []string {
	stop := fi.sValue + fi.sSize
	cmd := exec.Command("objdump", "--no-show-raw-insn", "--wide", "-dl",
		fmt.Sprintf("--start-address=0x%x", fi.sValue),
		fmt.Sprintf("--stop-address=0x%x", stop), loadmodule)
	b, err := cmd.CombinedOutput()
	if err != nil {
		warn("objdump of %s failed: %s\n", loadmodule, err)
		return nil
	}
	return strings.Split(string(b), "\n")
}

func collectParams(loadmodule string, fi *finfo) *proc.BinaryInfo {
	bi := proc.NewBinaryInfo(runtime.GOOS, runtime.GOARCH)
	bi.LoadBinaryInfo(loadmodule, 0, []string{})
	rdr := bi.Images[0].DwarfReader()
	rdr.Seek(dwarf.Offset(fi.dwOffset))
	rdr.Next()

	// Collect formal params.
	for {
		e, err := rdr.Next()
		if err != nil {
			warn("while reading param DWARF: %s", err)
			return nil
		}
		if e == nil || e.Tag == 0 {
			break
		}
		rdr.SkipChildren()
		if e.Tag != dwarf.TagFormalParameter {
			continue
		}
		if e.Val(dwarf.AttrName) == nil {
			continue
		}
		name := e.Val(dwarf.AttrName).(string)
		isvar := e.Val(dwarf.AttrVarParam).(bool)
		// skip all return arguments
		if isvar {
			continue
		}
		// skip _, no-name args
		if name == "_" || name == "" {
			continue
		}
		fi.params = append(fi.params, param{name: name, entry: *e})
	}
	verb(1, "found %d formal params for %s", len(fi.params), fi.name)

	return bi
}

func locateFuncDetails(loadmodule string, fcn string) finfo {
	rv := finfo{}
	rrv := finfo{}

	verb(1, "loading ELF for %s", loadmodule)
	f, eerr := elf.Open(loadmodule)
	if eerr != nil {
		warn("unable to open as ELF %s: %v\n", loadmodule, eerr)
		return rv
	}
	sslice, serr := f.Symbols()
	if serr != nil {
		warn("no ELF symbols for %s: %v\n", loadmodule, eerr)
		return rv
	}
	for _, s := range sslice {
		if s.Name == fcn {
			rrv.sValue = s.Value
			rrv.sSize = s.Size
			break
		}
	}
	if rrv.sValue == 0 {
		warn("could not locate %s in ELF symbol table\n", fcn)
		return rv
	}

	// Create DWARF reader
	d, derr := f.DWARF()
	verb(1, "loading DWARF for %s", loadmodule)
	if derr != nil {
		warn("error reading DWARF: %v", derr)
		return rv
	}
	rdr := d.Reader()

	// Construct an examiner.
	dwx, dwxerr := dwexaminer.NewDwExaminer(rdr)
	if dwxerr != nil {
		warn("error reading DWARF: %v", dwxerr)
		return rv
	}

	// Walk subprogram DIEs
	dieOffsets := dwx.DieOffsets()
	for idx := 0; idx < len(dieOffsets); idx++ {
		off := dieOffsets[idx]
		die, err := dwx.LoadEntryByOffset(off)
		if err != nil {
			warn("LoadEntryByOffset error reading DWARF: %v", err)
			return rv
		}
		if die.Tag == dwarf.TagCompileUnit {
			if name, ok := die.Val(dwarf.AttrName).(string); ok {
				verb(2, "compilation unit: %s", name)
			}
			continue
		}
		if die.Tag == dwarf.TagSubprogram {
			var lowpc uint64
			if nlowpc, ok := die.Val(dwarf.AttrLowpc).(uint64); ok {
				lowpc = nlowpc
			}
			verb(3, "examining subprogram DIE at offset 0x%x lowpc=0x%x", off, lowpc)
			if name, ok := die.Val(dwarf.AttrName).(string); ok {
				if name == fcn {
					verb(0, "found function %s at offset %x lowpc %x",
						fcn, off, lowpc)
					rrv.name = fcn
					rrv.dwLowPC = lowpc
					rrv.dwOffset = off
					rrv.valid = true
					return rrv
				}
			}
		}
		nidx, err := dwx.SkipChildren()
		if err != nil {
			warn("skipChildren error reading DWARF: %v", err)
			return rv
		}
		if nidx == -1 {
			// EOF
			break
		}

		// back up by 1 to allow for increment in for loop above
		idx = nidx - 1
		continue
	}
	warn("target function %q not found", fcn)
	return rv
}
