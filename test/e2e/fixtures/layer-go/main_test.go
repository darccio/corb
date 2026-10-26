package main

import "testing"

func TestPositive(t *testing.T) {
	if Sum(20, 22) != 42 {
		t.Fatal("wrong sum")
	}
}
func TestZero(t *testing.T) {
	if Sum(0, 0) != 0 {
		t.Fatal("wrong sum")
	}
}
func TestNegative(t *testing.T) {
	if Sum(-1, 1) != 0 {
		t.Fatal("wrong sum")
	}
}
