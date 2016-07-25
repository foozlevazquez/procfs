package procfs

import "testing"

func TestProcSmaps(t *testing.T) {
	p, err := FS("fixtures").NewProc(12933)
	if err != nil {
		t.Fatal(err)
	}

	s, err := p.NewSmaps()
	if err != nil {
		t.Fatal(err)
	}

	totals := s.MemStatsSummary()

	for _, test := range []struct {
		name string
		want int
		have int
	}{
		{name: "# Memstats", want: 421, have: len(s.MemStats), },
		{name: "Total PSS", want: 17820, have: int(totals.PSS), },
		{name: "Total Size", want: 381572, have: int(totals.Size), },
	} {
		if test.want != test.have {
			t.Errorf("want %s %d, have %d", test.name, test.want, test.have)
		}
	}

	for _, test := range []struct {
		name string
		want string
		have string
	}{
		{name: "map[0]",
			want: "/lib/x86_64-linux-gnu/libnss_nis-2.19.so",
			have: s.MemStats[0].FileName },
		{name: "map[420]",
			want: "[vsyscall]",
			have: s.MemStats[420].FileName, },
	} {
		if test.want != test.have {
			t.Errorf("want %s %q, have %q", test.name, test.want, test.have)
		}
	}

}

func TestProcSmaps1604(t *testing.T) {
	p, err := FS("fixtures").NewProc(1604)
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.NewSmaps()
	if err != nil {
		t.Fatal(err)
	}

	// totals := s.MemStatsSummary()

	// for _, test := range []struct {
	// 	name string
	// 	want int
	// 	have int
	// }{
	// 	{name: "# Memstats", want: 421, have: len(s.MemStats), },
	// 	{name: "Total PSS", want: 17820, have: int(totals.PSS), },
	// 	{name: "Total Size", want: 381572, have: int(totals.Size), },
	// } {
	// 	if test.want != test.have {
	// 		t.Errorf("want %s %d, have %d", test.name, test.want, test.have)
	// 	}
	// }

	// for _, test := range []struct {
	// 	name string
	// 	want string
	// 	have string
	// }{
	// 	{name: "map[0]",
	// 		want: "/lib/x86_64-linux-gnu/libnss_nis-2.19.so",
	// 		have: s.MemStats[0].FileName },
	// 	{name: "map[420]",
	// 		want: "[vsyscall]",
	// 		have: s.MemStats[420].FileName, },
	// } {
	// 	if test.want != test.have {
	// 		t.Errorf("want %s %q, have %q", test.name, test.want, test.have)
	// 	}
	// }

}


func testProcSmaps(pid int) (ProcSmaps, error) {
	p, err := FS("fixtures").NewProc(pid)
	if err != nil {
		return ProcSmaps{}, err
	}

	return p.NewSmaps()
}
