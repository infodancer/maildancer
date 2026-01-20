package maildir

import (
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/msgstore/errors"
)

func init() {
	msgstore.Register("maildir", func(config msgstore.StoreConfig) (msgstore.MsgStore, error) {
		if config.BasePath == "" {
			return nil, errors.ErrStoreConfigInvalid
		}
		// maildir_subdir specifies the subdirectory under each user (e.g., "Maildir")
		maildirSubdir := config.Options["maildir_subdir"]
		return NewStore(config.BasePath, maildirSubdir), nil
	})
}
