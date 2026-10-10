// Offline capture-filter compilation by ir_spoof; https://t.me/ir_spoof.
//go:build linux

package packet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// trustedHelper executes only a regular root-owned, non-writable executable.
// Argument arrays and offline pcap stdin prevent shell/filter interpolation and
// interface capture. A missing helper is an explicit error, not an ignored filter.
func trustedHelper(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("packet: install local %s for this option", name)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	var stat unix.Stat_t
	if unix.Stat(path, &stat) != nil || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("packet: trusted root-owned %s helper required", name)
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		if unix.Stat(directory, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 {
			return "", fmt.Errorf("packet: trusted helper directory required")
		}
		if directory == filepath.Dir(directory) {
			break
		}
	}
	return path, nil
}

type limitedCaptureOutput struct {
	bytes.Buffer
	limit int
}

func (w *limitedCaptureOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.Len() {
		return 0, fmt.Errorf("packet: helper output exceeds bound")
	}
	return w.Buffer.Write(p)
}

func compileCaptureFilter(expression string, snaplen int) ([]unix.SockFilter, error) {
	if len(expression) == 0 || len(expression) > 4096 || strings.IndexByte(expression, 0) >= 0 || snaplen < 68 || snaplen > 262144 {
		return nil, ErrPacket
	}
	filter, err := compileLibpcapFilter(expression, snaplen)
	if !errors.Is(err, errLibpcapUnavailable) {
		return filter, err
	}
	path, err := trustedHelper("tcpdump")
	if err != nil {
		return nil, err
	}
	var header [24]byte
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], uint32(snaplen))
	binary.LittleEndian.PutUint32(header[20:24], 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-ddd", "-r", "-", "--", expression)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(header[:])
	cmd.Stderr = io.Discard
	output := &limitedCaptureOutput{limit: 256 << 10}
	cmd.Stdout = output
	if err = cmd.Run(); err != nil {
		return nil, fmt.Errorf("packet: local capture filter could not be compiled")
	}
	fields := strings.Fields(output.String())
	if len(fields) == 0 {
		return nil, ErrPacket
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil || count < 1 || count > 4000 || len(fields) != 1+4*count {
		return nil, ErrPacket
	}
	filter = make([]unix.SockFilter, count)
	for i := range filter {
		values := []uint64{0, 0, 0, 0}
		for j, bits := range []int{16, 8, 8, 32} {
			values[j], err = strconv.ParseUint(fields[1+i*4+j], 10, bits)
			if err != nil {
				return nil, ErrPacket
			}
		}
		filter[i] = unix.SockFilter{Code: uint16(values[0]), Jt: uint8(values[1]), Jf: uint8(values[2]), K: uint32(values[3])}
	}
	return filter, nil
}

var errLibpcapUnavailable = errors.New("packet: trusted local libpcap unavailable")
var libpcapCompileMu sync.Mutex

type compiledPCAPProgram struct {
	Length       uint32
	Padding      uint32 // C pointer alignment on supported Linux amd64/arm64.
	Instructions unsafe.Pointer
}

// Only the optional expression compiler uses libpcap. Packet I/O and default
// builds remain pure Go. An absolute, root-owned system-library path avoids
// loading a caller-supplied search-path library; libpcap never opens a capture.
func compileLibpcapFilter(expression string, snaplen int) ([]unix.SockFilter, error) {
	if os.Getenv("LD_LIBRARY_PATH") != "" || os.Getenv("LD_PRELOAD") != "" || os.Getenv("LD_AUDIT") != "" {
		return nil, errLibpcapUnavailable
	}
	libpcapCompileMu.Lock()
	defer libpcapCompileMu.Unlock()
	paths := []string{
		"/usr/lib/x86_64-linux-gnu/libpcap.so.0.8", "/lib/x86_64-linux-gnu/libpcap.so.0.8",
		"/usr/lib/aarch64-linux-gnu/libpcap.so.0.8", "/lib/aarch64-linux-gnu/libpcap.so.0.8",
		"/usr/lib64/libpcap.so.1", "/lib64/libpcap.so.1", "/usr/lib/libpcap.so.1", "/usr/lib/libpcap.so",
	}
	var library uintptr
	for _, candidate := range paths {
		path, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		if unix.Stat(path, &stat) != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0022 != 0 {
			continue
		}
		trusted := true
		for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
			if unix.Stat(directory, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 {
				trusted = false
				break
			}
			if directory == filepath.Dir(directory) {
				break
			}
		}
		if !trusted {
			continue
		}
		library, err = purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err == nil {
			break
		}
	}
	if library == 0 {
		return nil, errLibpcapUnavailable
	}
	defer purego.Dlclose(library)
	compileAddress, err := purego.Dlsym(library, "pcap_compile_nopcap")
	if err != nil {
		return nil, errLibpcapUnavailable
	}
	freeAddress, err := purego.Dlsym(library, "pcap_freecode")
	if err != nil {
		return nil, errLibpcapUnavailable
	}
	var compile func(int32, int32, *compiledPCAPProgram, string, int32, uint32) int32
	var free func(*compiledPCAPProgram)
	purego.RegisterFunc(&compile, compileAddress)
	purego.RegisterFunc(&free, freeAddress)
	var program compiledPCAPProgram
	if compile(int32(snaplen), 1, &program, expression, 1, 0xffffffff) != 0 {
		return nil, fmt.Errorf("packet: invalid local capture filter")
	}
	defer free(&program)
	if program.Length == 0 || program.Length > 4000 || program.Instructions == nil {
		return nil, ErrPacket
	}
	return append([]unix.SockFilter(nil), unsafe.Slice((*unix.SockFilter)(program.Instructions), int(program.Length))...), nil
}

// tcpdump emits RET K instructions. A nonzero custom result jumps to the owned
// fixed-peer filter, while a zero result still rejects; neither can bypass it.
func combineCaptureFilters(custom, owned []unix.SockFilter) ([]unix.SockFilter, error) {
	if len(custom) == 0 || len(owned) == 0 || len(custom)+len(owned) > 4096 {
		return nil, ErrPacket
	}
	result := append([]unix.SockFilter(nil), custom...)
	for i, instruction := range result {
		if instruction.Code&7 == unix.BPF_RET {
			if instruction.Code != unix.BPF_RET|unix.BPF_K {
				return nil, fmt.Errorf("packet: dynamic capture return unsupported")
			}
			if instruction.K != 0 {
				result[i] = unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JA | unix.BPF_K, K: uint32(len(custom) - i - 1)}
			}
		} else if instruction.Code&7 == unix.BPF_JMP {
			if instruction.Code == unix.BPF_JMP|unix.BPF_JA|unix.BPF_K {
				if uint64(i)+1+uint64(instruction.K) >= uint64(len(custom)) {
					return nil, ErrPacket
				}
			} else if i+1+int(instruction.Jt) >= len(custom) || i+1+int(instruction.Jf) >= len(custom) {
				return nil, ErrPacket
			}
		}
	}
	return append(result, owned...), nil
}
