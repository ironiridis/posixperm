package posixperm

import (
	"encoding/json"
	"fmt"
	"testing"
)

type JSONType struct {
	P Perm
}

func TestValidImplicitOctal(t *testing.T) {
	var val uint32
	for val = 0o100; val < 0o1000; val++ {
		d := &JSONType{}
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"P": "%o"}`, val)), d)
		if err != nil {
			t.Errorf("got error on value %o: %v", val, err)
		}
		if d.P != Perm(val) {
			t.Errorf("got wrong value %o when parsing %o", d.P, val)
		}
	}
}

func TestInvalidImplicitOctal(t *testing.T) {
	C := []string{
		`{"P": "678"}`,
		`{"P": "999"}`,
		`{"P": "47777777777"}`,
	}

	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c), d)
		if err == nil {
			t.Errorf("got nil error for %q, unmarshaled to %v", c, d)
		}
	}
}

func TestValidExplicitOctal(t *testing.T) {
	var val uint32
	for val = 0o000; val < 0o1000; val++ {
		d := &JSONType{}
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"P": "0%03o"}`, val)), d)
		if err != nil {
			t.Errorf("got error on value %o: %v", val, err)
		}
		if d.P != Perm(val) {
			t.Errorf("got wrong value %o when parsing 0%03o", d.P, val)
		}
	}

	for val = 0o000; val < 0o1000; val++ {
		d := &JSONType{}
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"P": "%03O"}`, val)), d)
		if err != nil {
			t.Errorf("got error on value %o: %v", val, err)
		}
		if d.P != Perm(val) {
			t.Errorf("got wrong value %o when parsing 0%03O", d.P, val)
		}
	}
}

func TestInvalidExplicitOctal(t *testing.T) {
	C := []string{
		`{"P": "0678"}`,
		`{"P": "0o678"}`,
		`{"P": "0999"}`,
		`{"P": "0o999"}`,
		`{"P": "047777777777"}`,
		`{"P": "0o47777777777"}`,
	}

	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c), d)
		if err == nil {
			t.Errorf("got nil error for %q, unmarshaled to %v", c, d)
		}
	}
}

func TestValidSymbolic(t *testing.T) {
	C := []struct {
		j string
		v Perm
	}{
		{`{"P": "a=rwx"}`, 0o777},
		{`{"P": "a=rwx o-w"}`, 0o775},
		{`{"P": "a=rwxo-w"}`, 0o775},
		{`{"P": "u=x g=w o=r"}`, 0o124},
		{`{"P": "u+w u+r u+w"}`, 0o600},
		{`{"P": "u+wu=ru+wu-r"}`, 0o200},
		{`{"P": "a=rwx o-r a-w o-x o+r"}`, 0o554},
	}
	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c.j), d)
		if err != nil {
			t.Errorf("with %q, expected %04O. got error: %v", c.j, c.v, err)
		}
		if d.P != c.v {
			t.Errorf("with %q, expected %04O. got %04O", c.j, c.v, d.P)
		}
	}
}

func TestInvalidSymbolic(t *testing.T) {
	C := []string{
		`{"P": "a=rwz"}`,
		`{"P": "u=rw o+x m+w"}`,
		`{"P": "a=rwx o!x"}`,
		`{"P": "a=rwx g~x"}`,
	}

	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c), d)
		if err == nil {
			t.Errorf("got nil error for %q, unmarshaled to %04O", c, d.P)
		}
	}
}

func TestValidBasicSingle(t *testing.T) {
	C := []struct {
		j string
		v Perm
	}{
		{`{"P": "rwx"}`, 0o777},
		{`{"P": "r-x"}`, 0o555},
		{`{"P": "r--"}`, 0o444},
		{`{"P": "---"}`, 0o000},
	}
	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c.j), d)
		if err != nil {
			t.Errorf("with %q, expected %04O. got error: %v", c.j, c.v, err)
		}
		if d.P != c.v {
			t.Errorf("with %q, expected %04O. got %04O", c.j, c.v, d.P)
		}
	}
}

func TestInvalidBasicSingle(t *testing.T) {
	C := []string{
		`{"P": "rxw"}`,
		`{"P": "-r-"}`,
		`{"P": "rWx"}`,
	}

	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c), d)
		if err == nil {
			t.Errorf("got nil error for %q, unmarshaled to %04O", c, d.P)
		}
	}
}

func TestValidBasicTriple(t *testing.T) {
	C := []struct {
		j string
		v Perm
	}{
		{`{"P": "rwxrwxrwx"}`, 0o777},
		{`{"P": "rwxr-x---"}`, 0o750},
		{`{"P": "r---wx-w-"}`, 0o432},
		{`{"P": "---------"}`, 0o000},
	}
	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c.j), d)
		if err != nil {
			t.Errorf("with %q, expected %04O. got error: %v", c.j, c.v, err)
		}
		if d.P != c.v {
			t.Errorf("with %q, expected %04O. got %04O", c.j, c.v, d.P)
		}
	}
}

func TestInvalidBasicTriple(t *testing.T) {
	C := []string{
		`{"P": "rwxrmxrwx"}`,
		`{"P": "wrxwrxwrx"}`,
		`{"P": "rw?rwxrwx"}`,
	}

	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c), d)
		if err == nil {
			t.Errorf("got nil error for %q, unmarshaled to %04O", c, d.P)
		}
	}
}

func TestValidFull(t *testing.T) {
	C := []struct {
		j string
		v Perm
	}{
		{`{"P": "-rwxrwxrwx"}`, 0o777},
		{`{"P": "-rwxr-x---"}`, 0o750},
		{`{"P": "-r---wx-w-"}`, 0o432},
		{`{"P": "----------"}`, 0o000},
	}
	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c.j), d)
		if err != nil {
			t.Errorf("with %q, expected %04O. got error: %v", c.j, c.v, err)
		}
		if d.P != c.v {
			t.Errorf("with %q, expected %04O. got %04O", c.j, c.v, d.P)
		}
	}
}

func TestInvalidFull(t *testing.T) {
	C := []string{
		`{"P": "-rwxrmxrwx"}`,
		`{"P": "-wrxwrxwrx"}`,
		`{"P": "-rw?rwxrwx"}`,
	}

	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c), d)
		if err == nil {
			t.Errorf("got nil error for %q, unmarshaled to %04O", c, d.P)
		}
	}
}

func TestValidFullRoundTrip(t *testing.T) {
	C := []string{ // this json is sensitive to canonical representation
		`{"P":"drwxrwxrwx"}`,
		`{"P":"-rwxr-x---"}`,
		`{"P":"-r---wx-w-"}`,
		`{"P":"ugrwxr-xr-x"}`,
	}
	for _, c := range C {
		d := &JSONType{}
		err := json.Unmarshal([]byte(c), d)
		if err != nil {
			t.Errorf("with %q, got unmarshal error: %v", c, err)
		}
		e, err := json.Marshal(d)
		if err != nil {
			t.Errorf("with %q, got re-marshal error: %v", c, err)
		}
		if string(e) != c {
			t.Errorf("with %q, had intermediate %+v, but got %q", c, d, e)
		}
	}
}
