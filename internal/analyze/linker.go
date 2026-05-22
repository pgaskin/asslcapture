package analyze

import (
	"archive/zip"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

type File struct {
	*elf.File
	file   *os.File
	path   string
	offset int64
	size   int64
}

// Open opens an ELF from a path. It supports paths within zip files (if
// uncompressed) like the Android linker.
func Open(name string) (*File, error) {
	var ok bool

	full := name
	name, entry, isZip := strings.Cut(name, "!/")

	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", name, err)
	}
	defer func() {
		if !ok {
			f.Close()
		}
	}()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", name, err)
	}

	ff := &File{
		file: f,
		path: name,
		size: fi.Size(),
	}

	if isZip {
		z, err := zip.NewReader(ff.file, ff.size)
		if err != nil {
			return nil, err
		}
		i := slices.IndexFunc(z.File, func(zf *zip.File) bool {
			return zf.Name == entry
		})
		if i == -1 {
			return nil, fmt.Errorf("zip %q does not contain %q", name, entry)
		}
		zf := z.File[i]

		if zf.Method != zip.Store {
			return nil, fmt.Errorf("zip %q entry %q is compressed", name, entry)
		}

		off, err := zf.DataOffset()
		if err != nil {
			return nil, fmt.Errorf("read zip %q entry %q: %w", name, entry, err)
		}

		ff.offset = off
		ff.size = int64(zf.UncompressedSize64)
	}

	ff.File, err = elf.NewFile(ff.Data())
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", full, err)
	}

	ok = true
	return ff, nil
}

// Path gets the absolute path of the real file.
func (f *File) Path() string {
	return f.path
}

// Offset gets the offset of the ELF file into the real file, if any.
func (f *File) Offset() int64 {
	return f.offset
}

// Size gets the length of the ELF file.
func (f *File) Size() int64 {
	return f.size
}

// Data gets the contents of the file.
func (f *File) Data() interface {
	io.Reader
	io.ReaderAt
} {
	return io.NewSectionReader(f.file, f.offset, f.size)
}

// Close closes the file.
func (f *File) Close() error {
	return f.file.Close()
}
