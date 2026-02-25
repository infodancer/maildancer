package backend

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"
	"github.com/infodancer/maildancer/msgstore"
)

// Fetch retrieves message data.
func (s *Session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	ctx := context.Background()
	indices := s.resolveNumSet(numSet)

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		info := s.messages[idx]
		seqNum := uint32(idx + 1)
		uid := imap.UID(idx + 1)

		if err := s.fetchMessage(ctx, w, info, seqNum, uid, options); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) fetchMessage(ctx context.Context, w *imapserver.FetchWriter, info msgstore.MessageInfo, seqNum uint32, uid imap.UID, options *imap.FetchOptions) error {
	respW := w.CreateMessage(seqNum)

	if options.UID {
		respW.WriteUID(uid)
	}

	if options.Flags {
		imapFlags := make([]imap.Flag, len(info.Flags))
		for i, f := range info.Flags {
			imapFlags[i] = imap.Flag(f)
		}
		respW.WriteFlags(imapFlags)
	}

	needContent := options.Envelope || options.RFC822Size || options.InternalDate || len(options.BodySection) > 0 || options.BodyStructure != nil

	var content []byte
	if needContent {
		r, err := s.retrieveMessage(ctx, s.selectedMailbox, info.UID)
		if err != nil {
			_ = respW.Close()
			return err
		}
		content, err = io.ReadAll(r)
		r.Close()
		if err != nil {
			_ = respW.Close()
			return err
		}
	}

	if options.RFC822Size {
		size := info.Size
		if size == 0 {
			size = int64(len(content))
		}
		respW.WriteRFC822Size(size)
		s.collector.MessageFetched(s.userDomain, size)
	}

	if options.InternalDate {
		if !info.InternalDate.IsZero() {
			respW.WriteInternalDate(info.InternalDate)
		} else {
			respW.WriteInternalDate(time.Now())
		}
	}

	if options.Envelope {
		hdr, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(content)))
		if err == nil {
			respW.WriteEnvelope(imapserver.ExtractEnvelope(hdr))
		}
	}

	if options.BodyStructure != nil {
		respW.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(content)))
	}

	markSeen := false
	for _, section := range options.BodySection {
		sectionData := imapserver.ExtractBodySection(bytes.NewReader(content), section)
		wc := respW.WriteBodySection(section, int64(len(sectionData)))
		_, _ = wc.Write(sectionData)
		_ = wc.Close()

		if !section.Peek {
			markSeen = true
		}
	}

	if markSeen && !s.readOnly {
		if !hasFlag(info.Flags, imap.FlagSeen) {
			newFlags := applyStoreFlagsStr(info.Flags, &imap.StoreFlags{
				Op:    imap.StoreFlagsAdd,
				Flags: []imap.Flag{imap.FlagSeen},
			})
			if s.folderStore != nil {
				_ = s.folderStore.SetFlagsInFolder(ctx, s.mailbox, s.selectedMailbox, info.UID, newFlags)
				// Update in-memory state
				for i, m := range s.messages {
					if m.UID == info.UID {
						s.messages[i].Flags = newFlags
						break
					}
				}
			}
		}
	}

	return respW.Close()
}
