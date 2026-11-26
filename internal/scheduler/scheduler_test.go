package scheduler

import (
	"testing"
	"time"
	"uuid"
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

func TestChooseEvictionPicksLeastRecentlyUsedOnOneNode(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a, b := uuid.NewV7(), uuid.NewV7()
	nodes := []Node{
		{ID: a, Name: "a", MemoryMB: 1000, Millicores: 4000, ReservedMemoryMB: 900},
		{ID: b, Name: "b", MemoryMB: 1000, Millicores: 4000, ReservedMemoryMB: 950},
	}
	cand := func(node uuid.UUID, mem int64, idle time.Duration) Evictable {
		return Evictable{InstanceID: uuid.NewV7(), AppID: uuid.NewV7(), NodeID: node, MemoryMB: mem, Millicores: 100, LastActive: now.Add(-idle)}
	}
	oldest, older, recent := cand(a, 100, time.Hour), cand(a, 100, 10*time.Minute), cand(a, 400, 30*time.Second)
	onB := cand(b, 300, 2*time.Hour)
	cands := []Evictable{recent, older, oldest, onB}

	// 250 MB: node a needs two evictions (100 free + 100 + 100), node b one
	// (50 free + 300): fewer evictions win.
	node, victims, ok := ChooseEviction(nodes, cands, Request{MemoryMB: 250, Millicores: 100}, now, time.Minute)
	if !ok || node.ID != b || len(victims) != 1 || victims[0].InstanceID != onB.InstanceID {
		t.Fatalf("250 MB: node %s, victims %+v, %v", node.Name, victims, ok)
	}
	// 150 MB: one eviction on either node; on a the least recently used goes
	// (the hour-idle one), and b's candidate is even older: b's set wins.
	node, victims, ok = ChooseEviction(nodes, cands, Request{MemoryMB: 150, Millicores: 100}, now, time.Minute)
	if !ok || node.ID != b || victims[0].InstanceID != onB.InstanceID {
		t.Fatalf("150 MB: node %s, victims %+v", node.Name, victims)
	}
	// Without b, node a evicts in LRU order: the hour-idle app first, then
	// the 10-minute one; the app used 30 s ago is below the minimum idle.
	node, victims, ok = ChooseEviction(nodes[:1], cands, Request{MemoryMB: 250, Millicores: 100}, now, time.Minute)
	if !ok || node.ID != a || len(victims) != 2 || victims[0].InstanceID != oldest.InstanceID || victims[1].InstanceID != older.InstanceID {
		t.Fatalf("LRU order on a: %+v", victims)
	}
	// The recent app may not go, so 600 MB cannot be freed on a.
	if _, _, ok = ChooseEviction(nodes[:1], cands, Request{MemoryMB: 600, Millicores: 100}, now, time.Minute); ok {
		t.Fatal("evicted an app idle for less than the minimum")
	}
	// With a shorter minimum idle it can.
	if _, victims, ok = ChooseEviction(nodes[:1], cands, Request{MemoryMB: 600, Millicores: 100}, now, 10*time.Second); !ok || len(victims) != 3 {
		t.Fatalf("600 MB with every app evictable: %+v %v", victims, ok)
	}
	// Nothing evictable: no.
	if _, _, ok = ChooseEviction(nodes, nil, Request{MemoryMB: 150, Millicores: 100}, now, time.Minute); ok {
		t.Fatal("eviction without candidates")
	}
	// CPU counts too.
	cpu := []Node{{ID: a, Name: "a", MemoryMB: 10000, Millicores: 1000, ReservedMillicores: 1000}}
	if _, _, ok = ChooseEviction(cpu, []Evictable{cand(a, 10, time.Hour)}, Request{MemoryMB: 10, Millicores: 500}, now, time.Minute); ok {
		t.Fatal("evicting 100 millicores made room for 500")
	}
}
