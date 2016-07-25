package procfs

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"errors"
	"bufio"
	"strings"
	"strconv"
	"io"
)

// ProcSmaps provides memory information about the process,
// read from /proc/[pid]/smaps.

type ProcSmaps struct {
	// The process ID.
	PID int
	fs FS
	MemStats []*MemStat
}

type MemStat struct {
	VMStart uint64
	VMEnd uint64
	VMRead bool
	VMWrite bool
	VMExec bool
	VMMayShare bool

	PageOffset uint64

	MajorDev uint8
	MinorDev uint8

	Inode uint64
	FileName string

	Size uint64
	RSS uint64
	PSS uint64
	SharedClean uint64
	SharedDirty uint64
	PrivateClean uint64
	PrivateDirty uint64
	Referenced uint64
	Anonymous uint64
	AnonymousTHP uint64
	Swap uint64
	KernelPageSize uint64
	MMUPageSize uint64
	Locked uint64
	Nonlinear uint64

	VMFlags map[string]bool // too many bits
}

// NewStat returns the current status information of the process.
func (p Proc) NewSmaps() (ProcSmaps, error) {
	f, err := os.Open(p.path("smaps"))
	if err != nil {
		return ProcSmaps{}, err
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	r := bufio.NewReader(bytes.NewBuffer(data))

	if err != nil {
		return ProcSmaps{}, err
	}

	s := ProcSmaps{PID: p.PID, fs: p.fs}

	for {
		memStat, err := parseMemStat(r)
		if err != nil {
			if err == io.EOF {
				return s, nil
			} else {
				return ProcSmaps{}, err
			}
		}
		s.MemStats = append(s.MemStats, memStat)
	}
	return s, nil
}

// http://lxr.free-electrons.com/source/fs/proc/task_mmu.c

func parseMemStat(r *bufio.Reader) (*MemStat, error) {
	ms := &MemStat{ VMFlags: map[string]bool {}}

	err := ms.fillMemStatVM(r)
	if err != nil {
		return nil, err
	}

	err = ms.fillMemStat(r)
	if err != nil {
		return nil, err
	}

	return ms, nil
}

func (ms *MemStat) fillMemStat(r *bufio.Reader) error {
	type entry struct {
		fmt string
		ptr *uint64
	}

	entries := []entry {
		{ "Size", &ms.Size },
		{ "Rss", &ms.RSS },
		{ "Pss", &ms.PSS },
		{ "Shared_Clean", &ms.SharedClean },
		{ "Shared_Dirty", &ms.SharedDirty },
		{ "Private_Clean", &ms.PrivateClean },
		{ "Private_Dirty", &ms.PrivateDirty },
		{ "Referenced", &ms.Referenced },
		{ "Anonymous", &ms.Anonymous },
		{ "AnonHugePages", &ms.AnonymousTHP },
		{ "Swap", &ms.Swap },
		{ "KernelPageSize", &ms.KernelPageSize },
		{ "MMUPageSize", &ms.MMUPageSize },
		{ "Locked", &ms.Locked },
		// VmFlags
		// { "Linear", &ms.Nonlinear }, optional
	}

	for _, e := range entries {
		var line string
		var err error
		// Skip unknown entries
		for {
			line, err = r.ReadString('\n')
			if err != nil {
				return errors.New(fmt.Sprintf("Error reading %q line: %v",
					e.fmt, err))
			}
			if strings.HasPrefix(line, e.fmt + ":") {
				break
			}
			if strings.HasPrefix(line, "VmFlags:") {
				// Gone too far, error.
				return errors.New(fmt.Sprintf("Never reached %q line",
					e.fmt))
			}
			//fmt.Printf("Skipping %q (unmatched %q)\n", line, e.fmt + ":")
		}

		_fmt := fmt.Sprintf("%-16s%%8d kB\n", e.fmt + ":")
		_, err = fmt.Sscanf(line, _fmt, e.ptr)
		if err != nil {
			return errors.New(fmt.Sprintf("Line: %q: Error parsing: %q: %v",
				line, e.fmt, err))
		}
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	flags := strings.Split(line, " ")
	if flags[0] != "VmFlags:" {
		return errors.New(fmt.Sprintf("Error parsing VmFlags line: %q", line))
	}
	for _, flag := range flags[1:] {
		ms.VMFlags[flag] = true
	}
	if ms.VMFlags["nl"] {
		_, err := fmt.Fscanf(r, "Nonlinear:      %8d kB\n", &ms.Nonlinear)
		if err != nil {
			return errors.New(fmt.Sprintf("Error parsing Nonlinear: %v", err))
		}
	}
	return nil
}



func (ms *MemStat) fillMemStatVM(r *bufio.Reader) error {
	var flags string

	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}

	line = strings.TrimSuffix(line, "\n")
	parts := strings.Split(line, " ")

	vmParts := strings.Split(parts[0], "-")
	if len(vmParts) != 2 {
		return errors.New(fmt.Sprintf("Error parsing vm start/end: %q",
			parts[0]))
	}
	ms.VMStart, err = strconv.ParseUint(vmParts[0], 16, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing vm start: %q",
			vmParts[0]))
	}
	ms.VMEnd, err = strconv.ParseUint(vmParts[1], 16, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing vm start/end: %q",
			parts[0]))
	}


	flags = parts[1]

	ms.PageOffset, err =  strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing PageOffset: %q: %v",
			parts[2], err))
	}
	_, err =  fmt.Sscanf(parts[3], "%02x:%02x", &ms.MajorDev, &ms.MinorDev)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing devnos: %q: %v",
			parts[3], err))
	}

	ms.Inode, err =  strconv.ParseUint(parts[4], 10, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing inode: %q: %v",
			parts[4], err))
	}

	if len(parts) > 5 {
		ms.FileName = parts[len(parts) -1]
	}


	// Convert flag symbology
	if flags[0] == 'r' {
		ms.VMRead = true
	} else if flags[0] != '-' {
		return errors.New(fmt.Sprintf("Illegal VMRead smap flag value: %c",
			flags[0]))
	}
	if flags[1] == 'w' {
		ms.VMWrite = true
	} else if flags[1] != '-' {
		return errors.New(fmt.Sprintf("Illegal VMWrite smap flag value: %c",
			flags[1]))
	}
	if flags[2] == 'x' {
		ms.VMExec = true
	} else if flags[2] != '-' {
		return errors.New(fmt.Sprintf("Illegal VMExec smap flag value: %c",
			flags[2]))
	}
	if flags[3] == 's' {
		ms.VMMayShare = true
	} else if flags[3] != 'p' {
		return errors.New(fmt.Sprintf("Illegal VMMayShare smap flag value: %c",
			flags[3]))
	}

	// TODO: Trim filename?
	return nil
}

func (ps *ProcSmaps) MemStatsSummary() *MemStat {
	t := &MemStat{
		KernelPageSize: ps.MemStats[0].KernelPageSize,
		MMUPageSize: ps.MemStats[0].MMUPageSize,
	}

	for _, ms := range ps.MemStats {
		t.Size += ms.Size
		t.RSS += ms.RSS
		t.PSS += ms.PSS
		t.SharedClean += ms.SharedClean
		t.SharedDirty += ms.SharedDirty
		t.PrivateClean += ms.PrivateClean
		t.PrivateDirty += ms.PrivateDirty
		t.Referenced += ms.Referenced
		t.Anonymous += ms.Anonymous
		t.AnonymousTHP += ms.AnonymousTHP
		t.Swap += ms.Swap
		t.Locked += ms.Locked
		t.Nonlinear += ms.Nonlinear
	}
	return t
}
