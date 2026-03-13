package backend

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/infodancer/maildancer/msgstore"
)

// mockStore implements msgstore.MsgStore and msgstore.FolderStore for testing.
type mockStore struct {
	mu      sync.Mutex
	inbox   map[string][]msgstore.MessageInfo            // mailbox -> inbox messages
	folders map[string]map[string][]msgstore.MessageInfo // mailbox -> folder -> messages
	content map[uint32]string                            // uid -> content
	deleted map[uint32]bool                              // uid -> pending deletion
	uidSeq  uint32
}

func newMockStore() *mockStore {
	return &mockStore{
		inbox:   make(map[string][]msgstore.MessageInfo),
		folders: make(map[string]map[string][]msgstore.MessageInfo),
		content: make(map[uint32]string),
		deleted: make(map[uint32]bool),
	}
}

func (m *mockStore) nextUID() uint32 {
	m.uidSeq++
	return m.uidSeq
}

// addInboxMessage adds a message to the inbox for testing.
func (m *mockStore) addInboxMessage(mailbox string, flags []string, body string) msgstore.MessageInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	uid := m.nextUID()
	info := msgstore.MessageInfo{
		UID:          uid,
		Size:         int64(len(body)),
		Flags:        flags,
		InternalDate: time.Now(),
	}
	m.inbox[mailbox] = append(m.inbox[mailbox], info)
	m.content[uid] = body
	return info
}

// addFolderMessage adds a message to a folder for testing.
func (m *mockStore) addFolderMessage(mailbox, folder string, flags []string, body string) msgstore.MessageInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	uid := m.nextUID()
	info := msgstore.MessageInfo{
		UID:          uid,
		Size:         int64(len(body)),
		Flags:        flags,
		InternalDate: time.Now(),
	}
	if m.folders[mailbox] == nil {
		m.folders[mailbox] = make(map[string][]msgstore.MessageInfo)
	}
	m.folders[mailbox][folder] = append(m.folders[mailbox][folder], info)
	m.content[uid] = body
	return info
}

// -- msgstore.MessageStore --

func (m *mockStore) List(_ context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	msgs := m.inbox[mailbox]
	result := make([]msgstore.MessageInfo, len(msgs))
	copy(result, msgs)
	return result, nil
}

func (m *mockStore) Retrieve(_ context.Context, _ string, uid uint32) (io.ReadCloser, error) {
	m.mu.Lock()
	body, ok := m.content[uid]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("message not found: %d", uid)
	}
	return io.NopCloser(strings.NewReader(body)), nil
}

func (m *mockStore) Delete(_ context.Context, _ string, uid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted[uid] = true
	return nil
}

func (m *mockStore) Expunge(_ context.Context, mailbox string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var remaining []msgstore.MessageInfo
	for _, msg := range m.inbox[mailbox] {
		if !m.deleted[msg.UID] {
			remaining = append(remaining, msg)
		} else {
			delete(m.content, msg.UID)
			delete(m.deleted, msg.UID)
		}
	}
	m.inbox[mailbox] = remaining
	return nil
}

func (m *mockStore) Stat(_ context.Context, mailbox string) (int, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	msgs := m.inbox[mailbox]
	var total int64
	for _, msg := range msgs {
		total += msg.Size
	}
	return len(msgs), total, nil
}

// -- msgstore.DeliveryAgent --

func (m *mockStore) Deliver(_ context.Context, envelope msgstore.Envelope, r io.Reader) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	for _, rcpt := range envelope.Recipients {
		m.addInboxMessage(rcpt, nil, string(body))
	}
	return nil
}

// -- msgstore.FolderStore --

func (m *mockStore) CreateFolder(_ context.Context, mailbox string, folder string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.folders[mailbox] == nil {
		m.folders[mailbox] = make(map[string][]msgstore.MessageInfo)
	}
	if _, exists := m.folders[mailbox][folder]; exists {
		return fmt.Errorf("folder already exists: %s", folder)
	}
	m.folders[mailbox][folder] = nil
	return nil
}

func (m *mockStore) ListFolders(_ context.Context, mailbox string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var folders []string
	for folder := range m.folders[mailbox] {
		folders = append(folders, folder)
	}
	return folders, nil
}

func (m *mockStore) DeleteFolder(_ context.Context, mailbox string, folder string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.folders[mailbox] == nil {
		return fmt.Errorf("folder not found: %s", folder)
	}
	delete(m.folders[mailbox], folder)
	return nil
}

func (m *mockStore) ListInFolder(_ context.Context, mailbox string, folder string) ([]msgstore.MessageInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.folders[mailbox] == nil {
		return nil, nil
	}
	msgs := m.folders[mailbox][folder]
	result := make([]msgstore.MessageInfo, len(msgs))
	copy(result, msgs)
	return result, nil
}

func (m *mockStore) StatFolder(_ context.Context, mailbox string, folder string) (int, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.folders[mailbox] == nil {
		return 0, 0, nil
	}
	msgs := m.folders[mailbox][folder]
	var total int64
	for _, msg := range msgs {
		total += msg.Size
	}
	return len(msgs), total, nil
}

func (m *mockStore) RetrieveFromFolder(_ context.Context, _ string, _ string, uid uint32) (io.ReadCloser, error) {
	m.mu.Lock()
	body, ok := m.content[uid]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("message not found: %d", uid)
	}
	return io.NopCloser(strings.NewReader(body)), nil
}

func (m *mockStore) DeleteInFolder(_ context.Context, _ string, _ string, uid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted[uid] = true
	return nil
}

func (m *mockStore) ExpungeFolder(_ context.Context, mailbox string, folder string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.folders[mailbox] == nil {
		return nil
	}
	var remaining []msgstore.MessageInfo
	for _, msg := range m.folders[mailbox][folder] {
		if !m.deleted[msg.UID] {
			remaining = append(remaining, msg)
		} else {
			delete(m.content, msg.UID)
			delete(m.deleted, msg.UID)
		}
	}
	m.folders[mailbox][folder] = remaining
	return nil
}

func (m *mockStore) DeliverToFolder(_ context.Context, _ string, _ string, r io.Reader) error {
	// Consume the reader but don't store (simplified mock)
	_, err := io.ReadAll(r)
	return err
}

func (m *mockStore) RenameFolder(_ context.Context, mailbox string, oldName string, newName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.folders[mailbox] == nil {
		return fmt.Errorf("folder not found: %s", oldName)
	}
	msgs, exists := m.folders[mailbox][oldName]
	if !exists {
		return fmt.Errorf("folder not found: %s", oldName)
	}
	m.folders[mailbox][newName] = msgs
	delete(m.folders[mailbox], oldName)
	return nil
}

func (m *mockStore) AppendToFolder(_ context.Context, mailbox string, folder string, r io.Reader, flags []string, date time.Time) (uint32, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	uid := m.nextUID()
	info := msgstore.MessageInfo{
		UID:          uid,
		Size:         int64(len(body)),
		Flags:        flags,
		InternalDate: date,
	}
	if strings.EqualFold(folder, "INBOX") {
		m.inbox[mailbox] = append(m.inbox[mailbox], info)
	} else {
		if m.folders[mailbox] == nil {
			m.folders[mailbox] = make(map[string][]msgstore.MessageInfo)
		}
		m.folders[mailbox][folder] = append(m.folders[mailbox][folder], info)
	}
	m.content[uid] = string(body)
	return uid, nil
}

func (m *mockStore) SetFlagsInFolder(_ context.Context, mailbox string, folder string, uid uint32, flags []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.EqualFold(folder, "INBOX") {
		for i, msg := range m.inbox[mailbox] {
			if msg.UID == uid {
				m.inbox[mailbox][i].Flags = flags
				return nil
			}
		}
	} else {
		if m.folders[mailbox] != nil {
			for i, msg := range m.folders[mailbox][folder] {
				if msg.UID == uid {
					m.folders[mailbox][folder][i].Flags = flags
					return nil
				}
			}
		}
	}
	return fmt.Errorf("message not found: %d", uid)
}

func (m *mockStore) CopyMessage(_ context.Context, mailbox string, srcFolder string, uid uint32, destFolder string) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.content[uid]
	if !ok {
		return 0, fmt.Errorf("message not found: %d", uid)
	}
	newUID := m.nextUID()
	// Find source flags
	var srcFlags []string
	if strings.EqualFold(srcFolder, "INBOX") {
		for _, msg := range m.inbox[mailbox] {
			if msg.UID == uid {
				srcFlags = msg.Flags
				break
			}
		}
	}
	info := msgstore.MessageInfo{
		UID:          newUID,
		Size:         int64(len(body)),
		Flags:        srcFlags,
		InternalDate: time.Now(),
	}
	if strings.EqualFold(destFolder, "INBOX") {
		m.inbox[mailbox] = append(m.inbox[mailbox], info)
	} else {
		if m.folders[mailbox] == nil {
			m.folders[mailbox] = make(map[string][]msgstore.MessageInfo)
		}
		m.folders[mailbox][destFolder] = append(m.folders[mailbox][destFolder], info)
	}
	m.content[newUID] = body
	return newUID, nil
}

func (m *mockStore) UIDValidity(_ context.Context, _ string, _ string) (uint32, error) {
	return 12345, nil
}

func (m *mockStore) UIDNext(_ context.Context, _ string, _ string) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.uidSeq + 1, nil
}
