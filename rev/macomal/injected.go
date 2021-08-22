package main

import "C"

type E struct {
	val  byte
	next *E
}

func New(nn ...byte) *E {
	var head *E
	var previous *E

	for _, n := range nn {
		l := &E{val: n}
		if previous != nil {
			previous.next = l
		}
		if head == nil {
			head = l
		}
		previous = l
	}
	return head
}

//export TZj6iqF3jP
func TZj6iqF3jP() {
	_ = New('f')
	_ = New('l')
	_ = New('a')
	_ = New('g')
	_ = New('{')
	_ = New('}')
}

func main() {}
