// This package provides a Perm type that is assignable to/from an fs.FileMode and survives
// marshaling into and out of text. It supports a variety of conventional POSIX file permission
// notations for unmarshaling:
//
//	`rwx` -- assign read/write/execute across all users (including owner and group members)
//	`rw-` / `r-x` -- as above, dropping execute or write
//	`644` -- implied octal form, specifying read/write for owner, read-only for group/other
//	`0644` -- as above, but explicit octal form
//	`0o644` -- as above, but explicit octal form satisfying YAML 1.2 etc
//	`a=r` -- symbolic form assigning read permission to all
//	`a=rwx o-w` -- symbolic form assigning r/w/x to all but removing write from other
//	`ug=rx u+w` -- symbolic form granting read/execute to owner/group, adding write to owner
//	`ug=rxu+w` -- symbolic form as above but without space separator
//
// It's also possible to use long form permission styles:
//
//	`rwxr-xr-x` -- 'ls' style r/w/x for owner, and r/x for group/other
//	`-rwxr-xr-x` -- as above, but using the full 10+ byte syntax used by fs.FileMode
//	`ur-xr-x---` -- fs.FileMode syntax with owner/group read/execute plus setuid flag
package posixperm

import (
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
)

// a naked "644" style permissions expression
var fmtImplicitInt = regexp.MustCompile(`^[1-7][0-7]{2,}$`)

// a "0644" or "0o644" (eg Go and YAML 1.2) style permissions expression
var fmtExplicitInt = regexp.MustCompile(`^0o?[0-7]{3,}$`)

// a series of actor/modifier/permission tuples (eg "a=rwx o-w" or "u=rw g=r")
var fmtSymbolicMatch = regexp.MustCompile(`^((a|[ugo]{1,3})([-=+])([rwx]{1,3})\s?)+$`)
var fmtSymbolicExtract = regexp.MustCompile(`(a|[ugo]{1,3})([-=+])([rwx]{1,3})`)

// a single "rwx" shorthand applying the same permission to user/group/other
var fmtBasicSingle = regexp.MustCompile(`^(r|-)(w|-)(x|-)$`)

// all 9 permission bits in "ls" format (eg rwxrwxr-x for 0775)
var fmtBasicTriple = regexp.MustCompile(`^(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)$`)

// all (currently) defined fs.FileMode bits in the FileMode.String() format
var fmtFull = regexp.MustCompile(`^(-|[dalTLDpSugct?]*)(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)(r|-)(w|-)(x|-)$`)

// Perm represents an unsigned 32-bit integer that is comparable and assignable to fs.FileMode.
// It is intended to be embedded in structs that will be marshaled or unmarshaled, especially
// if reading human-edited files, as it allows a human to specify file permissions in a more
// conventional format than either a base-10 decimal rendering of the otherwise traditionally
// base-8 octal permissions, or an alternative like slices of flags.
type Perm fs.FileMode

func (p *Perm) fromImplicit(b []byte) error {
	v, err := strconv.ParseUint(string(b), 8, 32) // note base 8, because missing 0 prefix
	if err != nil {
		return fmt.Errorf("cannot parse implicit octal permission value %q: %w", b, err)
	}
	*p = Perm(v)
	return nil
}

func (p *Perm) fromExplicit(b []byte) error {
	v, err := strconv.ParseUint(string(b), 0, 32) // note base 0, to permit '0' and '0o' prefixes
	if err != nil {
		return fmt.Errorf("cannot parse octal permission value %q: %w", b, err)
	}
	*p = Perm(v)
	return nil
}

func (p *Perm) fromSymbolic(b []byte) error {
	matches := fmtSymbolicExtract.FindAllSubmatch(b, -1)
	// return fmt.Errorf("matches: %q", matches)
	var perm Perm
	for _, permexpr := range matches {
		var actor Perm
		for _, sym := range permexpr[1] {
			switch sym {
			case 'a': // a == all actors (u + g + o)
				actor = 0o777
			case 'u': // user owner actor
				actor = actor | 0o700
			case 'g': // group member actor
				actor = actor | 0o070
			case 'o': // other (neither user owner nor group member) actor
				actor = actor | 0o007
			}
		}
		var actorperm Perm
		for _, sym := range permexpr[3] {
			switch sym {
			case 'r':
				actorperm = actorperm | 0o444
			case 'w':
				actorperm = actorperm | 0o222
			case 'x':
				actorperm = actorperm | 0o111
			}
		}
		switch permexpr[2][0] {
		case '+':
			perm = perm | (actor & actorperm)
		case '-':
			perm = perm & ^(actor & actorperm)
		case '=':
			perm = (perm & ^actor) | (actor & actorperm)
		}
	}
	*p = perm
	return nil
}

func (p *Perm) fromBasicSingle(b []byte) error {
	// with a fixed-length format, we can directly interrogate the buffer.
	var perm Perm
	if b[0] == 'r' {
		perm = perm | 0o444
	}
	if b[1] == 'w' {
		perm = perm | 0o222
	}
	if b[2] == 'x' {
		perm = perm | 0o111
	}
	*p = perm
	return nil
}

func (p *Perm) fromBasicTriple(b []byte) error {
	// with a fixed-length format, we can directly interrogate the buffer.
	var perm Perm
	if b[0] == 'r' {
		perm = perm | 0o400
	}
	if b[1] == 'w' {
		perm = perm | 0o200
	}
	if b[2] == 'x' {
		perm = perm | 0o100
	}
	if b[3] == 'r' {
		perm = perm | 0o040
	}
	if b[4] == 'w' {
		perm = perm | 0o020
	}
	if b[5] == 'x' {
		perm = perm | 0o010
	}
	if b[6] == 'r' {
		perm = perm | 0o004
	}
	if b[7] == 'w' {
		perm = perm | 0o002
	}
	if b[8] == 'x' {
		perm = perm | 0o001
	}
	*p = perm
	return nil
}

func (p *Perm) fromFull(b []byte) error {
	m := fmtFull.FindSubmatch(b)

	var perm Perm
	for _, attr := range m[1] {
		switch attr {
		case 'd':
			perm = perm | Perm(fs.ModeDir)
		case 'a':
			perm = perm | Perm(fs.ModeAppend)
		case 'l':
			perm = perm | Perm(fs.ModeExclusive)
		case 'T':
			perm = perm | Perm(fs.ModeTemporary)
		case 'L':
			perm = perm | Perm(fs.ModeSymlink)
		case 'D':
			perm = perm | Perm(fs.ModeDevice)
		case 'p':
			perm = perm | Perm(fs.ModeNamedPipe)
		case 'S':
			perm = perm | Perm(fs.ModeSocket)
		case 'u':
			perm = perm | Perm(fs.ModeSetuid)
		case 'g':
			perm = perm | Perm(fs.ModeSetgid)
		case 'c':
			perm = perm | Perm(fs.ModeCharDevice)
		case 't':
			perm = perm | Perm(fs.ModeSticky)
		case '?':
			perm = perm | Perm(fs.ModeIrregular)
		case '-': // represents no special bits
		}
	}
	if m[2][0] == 'r' {
		perm = perm | 0o400
	}
	if m[3][0] == 'w' {
		perm = perm | 0o200
	}
	if m[4][0] == 'x' {
		perm = perm | 0o100
	}
	if m[5][0] == 'r' {
		perm = perm | 0o040
	}
	if m[6][0] == 'w' {
		perm = perm | 0o020
	}
	if m[7][0] == 'x' {
		perm = perm | 0o010
	}
	if m[8][0] == 'r' {
		perm = perm | 0o004
	}
	if m[9][0] == 'w' {
		perm = perm | 0o002
	}
	if m[10][0] == 'x' {
		perm = perm | 0o001
	}
	*p = perm
	return nil
}

// UnmarshalText implements encoding.TextUnmarshaler for this type. It checks for several conventional
// formats for basic file permissions, and also understands the full format returned by fs.FileMode's
// String() method.
func (p *Perm) UnmarshalText(b []byte) error {
	if fmtImplicitInt.Match(b) {
		return p.fromImplicit(b)
	}
	if fmtExplicitInt.Match(b) {
		return p.fromExplicit(b)
	}
	if fmtBasicSingle.Match(b) {
		return p.fromBasicSingle(b)
	}
	if fmtBasicTriple.Match(b) {
		return p.fromBasicTriple(b)
	}
	if fmtSymbolicMatch.Match(b) {
		return p.fromSymbolic(b)
	}
	if fmtFull.Match(b) {
		return p.fromFull(b)
	}
	return fmt.Errorf("unrecognized permission syntax %q", b)
}

// MarshalText implements encoding.TextMarshaler for this type. It returns the String() representation of
// fs.FileMode, which encodes each of the meaningful bits of the uint32 as a single byte; a dynamic set
// of mode, type, and behavior bits, or a dash if none are set, followed by 9 permission bits.
// MarshalText may return a format different than the format parsed if this type was unmarshaled as it
// always uses the full representation that is unambiguous and supports extended mode bits.
func (p Perm) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

// FromString parses the string p following the same rules as UnmarshalText, returning a new Perm. An
// error is returned if the string cannot be parsed as a Perm value.
func FromString(p string) (r Perm, err error) {
	err = r.UnmarshalText([]byte(p))
	return
}

// String returns the canonical fs.FileMode string representation of a Perm.
func (p Perm) String() string {
	return fs.FileMode(p).String()
}

// FromFileMode returns a new Perm copied from m. It never returns an error.
func FromFileMode(m fs.FileMode) (r Perm, err error) {
	r = Perm(m)
	return
}

// FileMode returns the fs.FileMode typed value of a Perm.
func (p Perm) FileMode() fs.FileMode {
	return fs.FileMode(p)
}
