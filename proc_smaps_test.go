package procfs

import "testing"

// 18.04.1
func TestProcSmaps7784(t *testing.T) {
	pid := 7784
	p, err := FS("fixtures").NewProc(pid)
	if err != nil {
		t.Fatal(err)
	}

	s, err := p.NewSmaps()
	if err != nil {
		t.Fatalf("Error parsing %d: %v", pid, err)
	}

	totals := s.MemStatsSummary()

	for _, test := range []struct {
		name string
		want int
		have int
	}{
		{name: "# Memstats", want: 483, have: len(s.MemStats), },
		{name: "Total PSS", want: 19970, have: int(totals.PSS), },
		{name: "Total Size", want: 512360, have: int(totals.Size), },
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
			want: "/opt/sp/php7.2/sbin/php-fpm",
			have: s.MemStats[0].FileName },
		{name: "map[420]",
			want: "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
			have: s.MemStats[420].FileName, },
	} {
		if test.want != test.have {
			t.Errorf("want %s %q, have %q", test.name, test.want, test.have)
		}
	}

}

func TestProcSmaps9141(t *testing.T) {
	pid := 9141
	p, err := FS("fixtures").NewProc(pid)
	if err != nil {
		t.Fatal(err)
	}

	s, err := p.NewSmaps()
	if err != nil {
		t.Fatalf("Error parsing %d: %v", pid, err)
	}

	totals := s.MemStatsSummary()

	for _, test := range []struct {
		name string
		want int
		have int
	}{
		{name: "# Memstats", want: 451, have: len(s.MemStats), },
		{name: "Total PSS", want: 13616, have: int(totals.PSS), },
		{name: "Total Size", want: 417220, have: int(totals.Size), },
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
			want: "/opt/sp/php7.2/sbin/php-fpm",
			have: s.MemStats[0].FileName },
		{name: "map[420]",
			want: "/lib/x86_64-linux-gnu/libreadline.so.6.3",
			have: s.MemStats[420].FileName, },
	} {
		if test.want != test.have {
			t.Errorf("want %s %q, have %q", test.name, test.want, test.have)
		}
	}

}
func TestProcSmaps12933(t *testing.T) {
	pid := 12933
	p, err := FS("fixtures").NewProc(pid)
	if err != nil {
		t.Fatal(err)
	}

	s, err := p.NewSmaps()
	if err != nil {
		t.Fatalf("Error parsing %d: %v", pid, err)
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

// Ubuntu 16.04.05
func TestProcSmaps19917(t *testing.T) {
	p, err := FS("fixtures").NewProc(19917)
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
		{name: "# Memstats", want: 542, have: len(s.MemStats), },
		{name: "Total PSS", want: 39426, have: int(totals.PSS), },
		{name: "Total Size", want: 707748, have: int(totals.Size), },
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
			want: "/opt/sp/php7.0/sbin/php-fpm",
			have: s.MemStats[0].FileName },
		{name: "map[420]",
			want: "/usr/lib/x86_64-linux-gnu/libcurl.so.4.4.0",
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
