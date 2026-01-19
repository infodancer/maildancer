package maildir

import (
	"io"
	"os"
	"path/filepath"

	"github.com/infodancer/maildancer/msgstore/errors"
)

// Maildir represents a single maildir directory.
type Maildir struct {
	path string
}

// New creates a Maildir instance for the given path.
// It does not create the directory; use Create() for that.
func New(path string) *Maildir {
	return &Maildir{path: path}
}

// Path returns the maildir path.
func (m *Maildir) Path() string {
	return m.path
}

// Create creates the maildir directory structure (new, cur, tmp).
func (m *Maildir) Create() error {
	dirs := []string{
		filepath.Join(m.path, "new"),
		filepath.Join(m.path, "cur"),
		filepath.Join(m.path, "tmp"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

// Exists checks if the maildir exists and has the required structure.
func (m *Maildir) Exists() bool {
	dirs := []string{
		filepath.Join(m.path, "new"),
		filepath.Join(m.path, "cur"),
		filepath.Join(m.path, "tmp"),
	}
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// Deliver writes a message to the maildir using the safe delivery process.
// It writes to tmp/ first, then moves to new/.
func (m *Maildir) Deliver(message io.Reader) (string, error) {
	if !m.Exists() {
		return "", errors.ErrMaildirNotFound
	}

	filename := generateFilename()
	tmpPath := filepath.Join(m.path, "tmp", filename)
	newPath := filepath.Join(m.path, "new", filename)

	// Write to tmp directory
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}

	_, err = io.Copy(f, message)
	if closeErr := f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}

	// Move from tmp to new
	if err := os.Rename(tmpPath, newPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}

	return filename, nil
}

// Folder returns a Maildir for a subfolder.
func (m *Maildir) Folder(name string) *Maildir {
	return New(filepath.Join(m.path, "."+name))
}

// CreateFolder creates a subfolder maildir.
func (m *Maildir) CreateFolder(name string) (*Maildir, error) {
	folder := m.Folder(name)
	if err := folder.Create(); err != nil {
		return nil, err
	}
	return folder, nil
}

// ListNew returns the filenames of messages in new/.
func (m *Maildir) ListNew() ([]string, error) {
	return m.listDir("new")
}

// ListCur returns the filenames of messages in cur/.
func (m *Maildir) ListCur() ([]string, error) {
	return m.listDir("cur")
}

func (m *Maildir) listDir(subdir string) ([]string, error) {
	dir := filepath.Join(m.path, subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.ErrMaildirNotFound
		}
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

// Open opens a message file for reading.
func (m *Maildir) Open(filename string) (*os.File, error) {
	// Try cur/ first, then new/
	curPath := filepath.Join(m.path, "cur", filename)
	if f, err := os.Open(curPath); err == nil {
		return f, nil
	}

	newPath := filepath.Join(m.path, "new", filename)
	return os.Open(newPath)
}

// Remove deletes a message file.
func (m *Maildir) Remove(filename string) error {
	// Try cur/ first, then new/
	curPath := filepath.Join(m.path, "cur", filename)
	if err := os.Remove(curPath); err == nil {
		return nil
	}

	newPath := filepath.Join(m.path, "new", filename)
	return os.Remove(newPath)
}

// MoveToSeen moves a message from new/ to cur/ (marks as seen).
func (m *Maildir) MoveToSeen(filename string) error {
	oldPath := filepath.Join(m.path, "new", filename)
	newPath := filepath.Join(m.path, "cur", filename)
	return os.Rename(oldPath, newPath)
}
