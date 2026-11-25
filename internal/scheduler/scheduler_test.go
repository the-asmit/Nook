package scheduler

import (
	"testing"
)

func node(name string, mem, cpu, resMem, resCPU int64, instances int32) Node {
	return Node{Name: name, MemoryMB: mem, Millicores: cpu, ReservedMemoryMB: resMem, ReservedMillicores: resCPU, Instances: instances}
}

func TestPickBestFit(t *testing.T) {
	tests := []struct {
		name  string
		nodes []Node
		req   Request
		want  string
	}{
		{
			name:  "least memory left that still fits",
			nodes: []Node{node("big", 8192, 4000, 0, 0, 0), node("small", 1024, 4000, 0, 0, 0), node("medium", 2048, 4000, 0, 0, 0)},
			req:   Request{MemoryMB: 900, Millicores: 100},
			want:  "small",
		},
		{
			name:  "reservations count",
			nodes: []Node{node("a", 4096, 4000, 3500, 0, 3), node("b", 4096, 4000, 1000, 0, 1)},
			req:   Request{MemoryMB: 1024, Millicores: 100},
			want:  "b",
		},
		{
			name:  "cpu must fit too",
			nodes: []Node{node("tight", 1024, 1000, 0, 900, 1), node("roomy", 4096, 4000, 0, 0, 0)},
			req:   Request{MemoryMB: 256, Millicores: 500},
			want:  "roomy",
		},
		{
			name:  "ties go to fewer instances",
			nodes: []Node{node("busy", 2048, 4000, 1024, 0, 4), node("quiet", 2048, 4000, 1024, 0, 1)},
			req:   Request{MemoryMB: 512, Millicores: 100},
			want:  "quiet",
		},
		{
			name:  "then to the name",
			nodes: []Node{node("n2", 2048, 4000, 0, 0, 0), node("n1", 2048, 4000, 0, 0, 0)},
			req:   Request{MemoryMB: 512, Millicores: 100},
			want:  "n1",
		},
		{
			name:  "exact fit",
			nodes: []Node{node("exact", 1024, 1000, 512, 500, 1)},
			req:   Request{MemoryMB: 512, Millicores: 500},
			want:  "exact",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Pick(tt.nodes, tt.req)
			if !ok || got.Name != tt.want {
				t.Fatalf("Pick = %q, %v; want %q", got.Name, ok, tt.want)
			}
		})
	}
}

func TestPickNothingFits(t *testing.T) {
	nodes := []Node{node("a", 1024, 1000, 1000, 0, 1), node("b", 512, 4000, 0, 0, 0), node("c", 8192, 1000, 0, 800, 1)}
	if got, ok := Pick(nodes, Request{MemoryMB: 600, Millicores: 300}); ok {
		t.Fatalf("Pick = %q; want no node", got.Name)
	}
	if _, ok := Pick(nil, Request{MemoryMB: 1, Millicores: 1}); ok {
		t.Fatal("Pick on no nodes succeeded")
	}
}

func TestConfigValidate(t *testing.T) {
	c := Config{ReservedMemoryMB: 512, ReservedMillicores: 250}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.ReservedMemoryMB = -1
	if err := c.Validate(); err == nil {
		t.Fatal("negative reserve accepted")
	}
}
