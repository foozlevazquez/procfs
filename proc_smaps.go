package procfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ProcSmaps provides memory information about the process,
// read from /proc/[pid]/smaps.

type ProcSmaps struct {
	// The process ID.
	PID      int
	fs       FS
	MemStats []*MemStat
}

type MemStat struct {
	VMStart    uint64
	VMEnd      uint64
	VMRead     bool
	VMWrite    bool
	VMExec     bool
	VMMayShare bool

	PageOffset uint64

	MajorDev uint8
	MinorDev uint8

	Inode    uint64
	FileName string

	Size           uint64
	RSS            uint64
	PSS            uint64
	SharedClean    uint64
	SharedDirty    uint64
	PrivateClean   uint64
	PrivateDirty   uint64
	Referenced     uint64
	Anonymous      uint64
	AnonymousTHP   uint64
	Swap           uint64
	KernelPageSize uint64
	MMUPageSize    uint64
	Locked         uint64
	Nonlinear      uint64

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
}

// http://lxr.free-electrons.com/source/fs/proc/task_mmu.c

// Each section of smaps file consists of two areas (that we care about):
//
// fillMemStatVM() reads "55acbeace000- ... /opt/sp/php7.0/sbin/php-fpm"
// fillMemStat() reads rest of entries ("Size: ... kB")
//
// If fillMemStatVM hits EOF that's ok, it is the EOF at the appropriate
// place, anywhere else it's an error.

func parseMemStat(r *bufio.Reader) (*MemStat, error) {
	ms := &MemStat{VMFlags: map[string]bool{}}

	err := ms.fillMemStatVM(r)
	if err != nil {
		return nil, err
	}

	err = ms.fillMemStat(r)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error filling mem stats: %q: %v",
			ms.FileName, err))
	}

	return ms, nil
}

type entry struct {
	ptr      *uint64
	found    bool
	optional bool
}

func (ms *MemStat) mkEntryMap() map[string]*entry {
	return map[string]*entry{
		"Size":           {ptr: &ms.Size, found: false, optional: false},
		"Rss":            {ptr: &ms.RSS, found: false, optional: true},
		"Pss":            {ptr: &ms.PSS, found: false, optional: false},
		"Shared_Clean":   {ptr: &ms.SharedClean, found: false, optional: true},
		"Shared_Dirty":   {ptr: &ms.SharedDirty, found: false, optional: true},
		"Private_Clean":  {ptr: &ms.PrivateClean, found: false, optional: true},
		"Private_Dirty":  {ptr: &ms.PrivateDirty, found: false, optional: false},
		"Referenced":     {ptr: &ms.Referenced, found: false, optional: false},
		"Anonymous":      {ptr: &ms.Anonymous, found: false, optional: true},
		"AnonHugePages":  {ptr: &ms.AnonymousTHP, found: false, optional: false},
		"Swap":           {ptr: &ms.Swap, found: false, optional: false},
		"KernelPageSize": {ptr: &ms.KernelPageSize, found: false, optional: false},
		"MMUPageSize":    {ptr: &ms.MMUPageSize, found: false, optional: true},
		"Locked":         {ptr: &ms.Locked, found: false, optional: false},

		// Linear is optional, but since we aren't insisting on a strict order
		// any more, we include it.
		"Linear": {ptr: &ms.Nonlinear, found: false, optional: true},
	}
}

var prevLine = "<BOF>"
var eRE = regexp.MustCompile(
	"^([[:word:]]+):[[:space:]]*([[:digit:]]+) kB\n$")

// Read up to the VmFlags line filling in the MemStat entries.
//
func (ms *MemStat) fillMemStat(r *bufio.Reader) error {
	// Due to changing order of smaps entries (notably Ubuntu 16.04.5), we
	// don't expect the smap entries to be in a certain order, but instead use
	// a map to note the stats and record if they have been seen.

	// Smap section entries map[string]entry
	entries := ms.mkEntryMap()

	// Iterate over the lines of the smap section, afterwards return error if
	// we didn't see a particular entry.  Terminates when we hit the "VmFlags"
	// line.

	for done := false; !done; {
		line, err := r.ReadString('\n')
		if err != nil {
			return errors.New(fmt.Sprintf(
				"Error reading line: %v.  Prevline: %q", err, prevLine))
		}

		matches := eRE.FindStringSubmatch(line)
		//fmt.Printf("Line = %q, Matches = %#v\n", line, matches)
		if matches != nil {
			// Do we care about this entry type
			en, ok := entries[matches[1]]
			if ok {
				// Found corresponding entry, record value
				ui, err := strconv.ParseUint(matches[2], 10, 64)
				if err != nil {
					return errors.New(fmt.Sprintf(
						"Can't parse int value: %q, line %q, prev line: %q",
						matches[2], line, prevLine))
				}
				*en.ptr = ui
				en.found = true
			}
			// We don't care about this entry type, skip.
		} else {
			// Not a typical entry line.
			if strings.HasPrefix(line, "VmFlags:") {
				if err = ms.parseVmFlags(line); err != nil {
					return errors.New(fmt.Sprintf(
						"Error parsing VmFlags: %v, line %q, prev line: %q",
						err, line, prevLine))
				}
				done = true
			} else {
				return errors.New(fmt.Sprintf(
					"Unknown smap line: %q, prev line: %q", line, prevLine))
			}
		}
		prevLine = line
	}
	// Done with the section, check for unfilled entries.
	for es, en := range entries {
		if !en.found && !en.optional {
			return errors.New(fmt.Sprintf(
				"Never got %q entry. last line: %q", es, prevLine))
		}
	}

	return nil
}

func (ms *MemStat) parseVmFlags(line string) error {
	flags := strings.Split(line, " ")
	if flags[0] != "VmFlags:" {
		return errors.New(fmt.Sprintf("Error parsing VmFlags line: %q", line))
	}
	for _, flag := range flags[1:] {
		ms.VMFlags[flag] = true
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

	ms.PageOffset, err = strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing PageOffset: %q: %v",
			parts[2], err))
	}
	_, err = fmt.Sscanf(parts[3], "%02x:%02x", &ms.MajorDev, &ms.MinorDev)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing devnos: %q: %v",
			parts[3], err))
	}

	ms.Inode, err = strconv.ParseUint(parts[4], 10, 64)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing inode: %q: %v",
			parts[4], err))
	}

	if len(parts) > 5 {
		ms.FileName = parts[len(parts)-1]
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
		MMUPageSize:    ps.MemStats[0].MMUPageSize,
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
