package main

import (
	"reflect"
	"testing"
)

func TestSummaryTotalsAndOrder(t *testing.T) {
	input := map[string][]int{"beta": {9, 5, 7}, "alpha": {4, 1, 3, 2}}
	got, err := summarize(input)
	if err != nil || len(got) != 2 {
		t.Fatalf("summarize: %v, %v", got, err)
	}
	if got[0].Name != "alpha" || got[0].Count != 4 || got[0].Total != 10 || got[1].Total != 21 {
		t.Fatalf("wrong summaries: %+v", got)
	}
	if !reflect.DeepEqual(input["alpha"], []int{4, 1, 3, 2}) {
		t.Fatal("input changed")
	}
}

func TestPermutationHasSameDigest(t *testing.T) {
	first, _ := summarize(map[string][]int{"sample": {2, 1, 3}})
	second, _ := summarize(map[string][]int{"sample": {3, 2, 1}})
	if len(first[0].Digest) != 64 || !reflect.DeepEqual(first, second) {
		t.Fatalf("unstable summary: %v != %v", first, second)
	}
}

func TestEmptyInputRejected(t *testing.T) {
	if _, err := summarize(nil); err == nil {
		t.Fatal("empty input accepted")
	}
}
