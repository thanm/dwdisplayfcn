// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//
// This program reads in DWARF info for a given load module (shared
// library or executable), picks out a specific function, and displays
// info from the DWARF about the function.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"github.com/thanm/dwdisplayfcn/examine"
)

var verbflag = flag.Int("v", 0, "Verbose trace output level")
var fcnflag = flag.String("f", "", "name of function to display")
var moduleflag = flag.String("m", "", "load module to read")
var dumpbiflag = flag.Bool("dbi", false, "dump runtime/debug build info")

func verb(vlevel int, s string, a ...interface{}) {
	if *verbflag >= vlevel {
		fmt.Printf(s, a...)
		fmt.Printf("\n")
	}
}

func warn(s string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, s, a...)
	fmt.Fprintf(os.Stderr, "\n")
}

func usage(msg string) {
	if len(msg) > 0 {
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	}
	fmt.Fprintf(os.Stderr, "usage: dwdisplayfcn [flags] <ELF files>\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func dumpBuildInfo() {
	bip, ok := debug.ReadBuildInfo()
	if !ok {
		println("no build info")
	} else {
		println("goversion", bip.GoVersion)
		println("main package path", bip.Path)
		fmt.Printf("main mod: %+v\n", bip.Main)
		for k, dep := range bip.Deps {
			fmt.Printf("  dep %d: %+v\n", k, dep)
		}
	}
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("dwdisplayfcn: ")
	flag.Parse()
	verb(1, "in main")
	if *dumpbiflag {
		dumpBuildInfo()
	}
	if *fcnflag == "" || *moduleflag == "" {
		usage("please supply -f and -m options")
	}
	if flag.NArg() != 0 {
		usage("unexpected additional arguments")
	}
	examine.ExamineFile(*moduleflag, *fcnflag)
	verb(1, "leaving main")
}
