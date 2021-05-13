
This program, dwdisplayfcn, provides a tool for displaying DWARF location
expression information for variables and parameters alonside the assembly for a
compiled Go function. Example:

```
$ cat small.go
package main

//go:noinline
func ABC(s string, t int) int {
	return len(s) + t
}

func main() {
	println(ABC("foo", 9))
}
$ go build -gcflags="-l -N" small.go
$ ./dwdisplayfcn -f main.ABC -m small
found function main.ABC at offset 3e4de lowpc 4553a0
...

Disassembly of section .text:

00000000004553a0 <main.ABC>:
main.ABC():
/home/thanm/small.go:4
  4553a0:	sub    $0x18,%rsp
 ^ "s" now in: { [0: S=8 reg=RAX] [1: S=8 reg=RBX]
 ^ "t" now in: { [0: S=0 reg=RCX]
  4553a4:	mov    %rbp,0x10(%rsp)
  4553a9:	lea    0x10(%rsp),%rbp
...
$
```

Under the hood, dwdisplayfcn uses a combination of the Golang
standard library's "debug/dwarf" package, plus a set of APIs exported
by Delve for examining program debug info.

