package smtp

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/smtpd/config"
)

func TestHandlerSysProcAttr_DefaultIsNil(t *testing.T) {
	cfg := config.Default()
	if got := handlerSysProcAttr(cfg); got != nil {
		t.Errorf("handlerSysProcAttr(default) = %+v, want nil", got)
	}
}

func TestHandlerSysProcAttr_CredentialDrop(t *testing.T) {
	cfg := config.Default()
	cfg.HandlerUID = 903
	cfg.HandlerGID = 900
	cfg.HandlerGroups = []uint32{901, 902}

	attr := handlerSysProcAttr(cfg)
	if attr == nil {
		t.Fatal("handlerSysProcAttr() = nil, want credential drop")
	}
	if attr.Credential == nil {
		t.Fatal("Credential = nil, want uid/gid set")
	}
	if attr.Credential.Uid != 903 {
		t.Errorf("Uid = %d, want 903", attr.Credential.Uid)
	}
	if attr.Credential.Gid != 900 {
		t.Errorf("Gid = %d, want 900", attr.Credential.Gid)
	}
	if !reflect.DeepEqual(attr.Credential.Groups, []uint32{901, 902}) {
		t.Errorf("Groups = %v, want [901 902]", attr.Credential.Groups)
	}
	if !attr.Setpgid {
		t.Error("Setpgid = false, want true")
	}
}

func TestHandlerSysProcAttr_UIDOnly(t *testing.T) {
	cfg := config.Default()
	cfg.HandlerUID = 903

	attr := handlerSysProcAttr(cfg)
	if attr == nil || attr.Credential == nil {
		t.Fatal("handlerSysProcAttr() missing credential")
	}
	if attr.Credential.Uid != 903 || attr.Credential.Gid != 0 {
		t.Errorf("credential = %d/%d, want 903/0", attr.Credential.Uid, attr.Credential.Gid)
	}
	if len(attr.Credential.Groups) != 0 {
		t.Errorf("Groups = %v, want empty", attr.Credential.Groups)
	}
}

func TestHandlerEnv_ConnectionMetadata(t *testing.T) {
	cfg := config.Default()
	env := handlerEnv(cfg, "192.0.2.1", config.ModeSubmission)

	if !slices.Contains(env, "SMTPD_CLIENT_IP=192.0.2.1") {
		t.Errorf("env missing SMTPD_CLIENT_IP: %v", env)
	}
	if !slices.Contains(env, "SMTPD_LISTENER_MODE=submission") {
		t.Errorf("env missing SMTPD_LISTENER_MODE: %v", env)
	}
}

func TestHandlerEnv_PropagatesEffectiveTLS(t *testing.T) {
	cfg := config.Default()
	cfg.TLS.CertFile = "/run/tls/smtpd/fullchain.pem"
	cfg.TLS.KeyFile = "/run/tls/smtpd/privkey.pem"

	env := handlerEnv(cfg, "192.0.2.1", config.ModeSmtp)

	if !slices.Contains(env, "SMTPD_TLS_CERT_FILE=/run/tls/smtpd/fullchain.pem") {
		t.Errorf("env missing SMTPD_TLS_CERT_FILE: %v", env)
	}
	if !slices.Contains(env, "SMTPD_TLS_KEY_FILE=/run/tls/smtpd/privkey.pem") {
		t.Errorf("env missing SMTPD_TLS_KEY_FILE: %v", env)
	}
}

func TestHandlerEnv_EmptyTLSOmitted(t *testing.T) {
	cfg := config.Default()
	env := handlerEnv(cfg, "192.0.2.1", config.ModeSmtp)

	for _, e := range env {
		if strings.HasPrefix(e, "SMTPD_TLS_CERT_FILE=") || strings.HasPrefix(e, "SMTPD_TLS_KEY_FILE=") {
			t.Errorf("unexpected TLS override in env: %q", e)
		}
	}
}
