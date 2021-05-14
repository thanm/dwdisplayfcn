package main

//go:noinline
func ABC(x, y, z int, s1, s2, s3 string, f1, f2, f3 float64) int {
	rv := 0
	if f1+f2+f3 < 100 {
		rv = 101
	}
	rv += x + y + z + len(s1) + len(s2) + len(s3)
	return rv
}

func main() {
	println(ABC(1, 2, 3, "foo", "blix", "bazbaz", 3.0, 9.0, 17.0))
}
