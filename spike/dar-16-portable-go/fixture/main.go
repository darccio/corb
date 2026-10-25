package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

type Summary struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Total  int    `json:"total"`
	Digest string `json:"digest"`
}

func summarize(input map[string][]int) ([]Summary, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	results := make(chan Summary, len(input))
	var workers sync.WaitGroup
	for name, values := range input {
		workers.Go(func() {
			numbers := append([]int(nil), values...)
			sort.Ints(numbers)
			encoded, _ := json.Marshal(numbers)
			digest := sha256.Sum256(encoded)
			item := Summary{Name: name, Count: len(numbers), Digest: hex.EncodeToString(digest[:])}
			for _, value := range numbers {
				item.Total += value
			}
			results <- item
		})
	}
	workers.Wait()
	close(results)
	output := make([]Summary, 0, len(input))
	for item := range results {
		output = append(output, item)
	}
	sort.Slice(output, func(i, j int) bool { return output[i].Name < output[j].Name })
	return output, nil
}

func main() {
	data, err := os.ReadFile("input.json")
	if err != nil {
		panic(err)
	}
	var input map[string][]int
	if err := json.Unmarshal(data, &input); err != nil {
		panic(err)
	}
	output, err := summarize(input)
	if err != nil {
		panic(err)
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("report.json", append(encoded, '\n'), 0o644); err != nil {
		panic(err)
	}
	fmt.Println(string(encoded))
}
