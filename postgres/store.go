// Package scoped provides authenticated, transaction-scoped access to a
// Codefly Postgres service. It deliberately has no admin capability: schema
// ownership and cross-tenant maintenance belong to separately wired control
// plane dependencies, never to request handlers.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUnauthenticated = errors.New("postgres scope requires an authenticated principal")
	ErrUnauthorized    = errors.New("postgres write capability is not authorized")
)

// Principal is the minimal authenticated identity required by tenant RLS.
// Applications adapt their verified auth/proto identity to this interface at
// the request boundary; repositories never accept tenant or user IDs directly.
type Principal interface {
	DatabaseTenantID() string
	DatabaseUserID() string
}

// Authenticator resolves an already verified principal from context and owns
// the application-specific decision to issue a write capability.
type Authenticator interface {
	AuthenticatedPrincipal(context.Context) (Principal, error)
	AuthorizeDatabaseWrite(context.Context, Principal) error
}

// ReadTx intentionally exposes query operations only. Even if it is
// circumvented, the transaction and its dedicated credential are read-only at
// the database layer as defense in depth.
type ReadTx interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// WriteTx adds mutation to ReadTx. A writer may query to enforce invariants;
// a reader can never obtain Exec through this API.
type WriteTx interface {
	ReadTx
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type config struct {
	tenantSetting string
	userSetting   string
}

// Option configures the RLS settings used by application policies.
type Option func(*config) error

// WithScopeSettings changes the transaction-local Postgres settings. Custom
// settings must use the extension-style namespace required by Postgres, e.g.
// "app.current_tenant_id" and "app.current_user_id".
func WithScopeSettings(tenantSetting, userSetting string) Option {
	return func(configuration *config) error {
		if err := validateSettingName(tenantSetting); err != nil {
			return fmt.Errorf("tenant setting: %w", err)
		}
		if err := validateSettingName(userSetting); err != nil {
			return fmt.Errorf("user setting: %w", err)
		}
		if tenantSetting == userSetting {
			return errors.New("tenant and user settings must be distinct")
		}
		configuration.tenantSetting = tenantSetting
		configuration.userSetting = userSetting
		return nil
	}
}

// Factory owns the private reader/writer pools and converts authenticated
// request context into bound capabilities. It never exposes either raw pool.
type Factory struct {
	reader        transactionBeginner
	writer        transactionBeginner
	authenticator Authenticator
	config        config
}

// NewFactory constructs the request-time database boundary. The pools must be
// built from Codefly's read-only-connection and read-write-connection secrets,
// respectively.
func NewFactory(reader, writer *pgxpool.Pool, authenticator Authenticator, options ...Option) (*Factory, error) {
	if reader == nil {
		return nil, errors.New("read-only Postgres pool is required")
	}
	if writer == nil {
		return nil, errors.New("read-write Postgres pool is required")
	}
	return newFactory(poolBeginner{pool: reader}, poolBeginner{pool: writer}, authenticator, options...)
}

func newFactory(reader, writer transactionBeginner, authenticator Authenticator, options ...Option) (*Factory, error) {
	if reader == nil || writer == nil {
		return nil, errors.New("Postgres transaction beginners are required")
	}
	if authenticator == nil {
		return nil, errors.New("Postgres authenticator is required")
	}
	configuration := config{
		tenantSetting: "codefly.current_tenant_id",
		userSetting:   "codefly.current_user_id",
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&configuration); err != nil {
			return nil, err
		}
	}
	return &Factory{
		reader:        reader,
		writer:        writer,
		authenticator: authenticator,
		config:        configuration,
	}, nil
}

// Reader resolves the authenticated principal and returns a bound read-only
// capability. It does not authorize or construct a writer.
func (f *Factory) Reader(ctx context.Context) (*Reader, error) {
	_, scope, err := f.principal(ctx)
	if err != nil {
		return nil, err
	}
	return &Reader{beginner: f.reader, scope: scope}, nil
}

// Writer resolves the authenticated principal and requires an explicit
// application authorization decision before returning a write capability.
func (f *Factory) Writer(ctx context.Context) (*Writer, error) {
	principal, scope, err := f.principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := f.authenticator.AuthorizeDatabaseWrite(ctx, principal); err != nil {
		return nil, errors.Join(ErrUnauthorized, err)
	}
	return &Writer{beginner: f.writer, scope: scope}, nil
}

func (f *Factory) principal(ctx context.Context) (Principal, transactionScope, error) {
	if ctx == nil {
		return nil, transactionScope{}, ErrUnauthenticated
	}
	principal, err := f.authenticator.AuthenticatedPrincipal(ctx)
	if err != nil {
		return nil, transactionScope{}, errors.Join(ErrUnauthenticated, err)
	}
	if isNil(principal) {
		return nil, transactionScope{}, ErrUnauthenticated
	}
	tenantID := strings.TrimSpace(principal.DatabaseTenantID())
	userID := strings.TrimSpace(principal.DatabaseUserID())
	if tenantID == "" || userID == "" {
		return nil, transactionScope{}, ErrUnauthenticated
	}
	return principal, transactionScope{
		tenantSetting: f.config.tenantSetting,
		tenantID:      tenantID,
		userSetting:   f.config.userSetting,
		userID:        userID,
	}, nil
}

// Reader is an authenticated, principal-bound read capability.
type Reader struct {
	beginner transactionBeginner
	scope    transactionScope
}

// InTransaction runs fn in a database-enforced read-only transaction after
// installing tenant/user scope with transaction-local settings.
func (r *Reader) InTransaction(ctx context.Context, fn func(context.Context, ReadTx) error) error {
	if fn == nil {
		return errors.New("read transaction callback is required")
	}
	return runTransaction(ctx, r.beginner, r.scope, pgx.ReadOnly, func(ctx context.Context, tx transaction) error {
		return fn(ctx, readTx{tx: tx})
	})
}

// Writer is an authenticated, authorized, principal-bound write capability.
type Writer struct {
	beginner transactionBeginner
	scope    transactionScope
}

// InTransaction runs fn in a read-write transaction after installing
// transaction-local tenant/user scope.
func (w *Writer) InTransaction(ctx context.Context, fn func(context.Context, WriteTx) error) error {
	if fn == nil {
		return errors.New("write transaction callback is required")
	}
	return runTransaction(ctx, w.beginner, w.scope, pgx.ReadWrite, func(ctx context.Context, tx transaction) error {
		return fn(ctx, writeTx{tx: tx})
	})
}

type transactionScope struct {
	tenantSetting string
	tenantID      string
	userSetting   string
	userID        string
}

type transactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (transaction, error)
}

type transaction interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

type poolBeginner struct {
	pool *pgxpool.Pool
}

func (p poolBeginner) BeginTx(ctx context.Context, options pgx.TxOptions) (transaction, error) {
	return p.pool.BeginTx(ctx, options)
}

type readTx struct {
	tx transaction
}

func (r readTx) Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error) {
	return r.tx.Query(ctx, sql, arguments...)
}

func (r readTx) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	return r.tx.QueryRow(ctx, sql, arguments...)
}

type writeTx struct {
	tx transaction
}

func (w writeTx) Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error) {
	return w.tx.Query(ctx, sql, arguments...)
}

func (w writeTx) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	return w.tx.QueryRow(ctx, sql, arguments...)
}

func (w writeTx) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	return w.tx.Exec(ctx, sql, arguments...)
}

func runTransaction(
	ctx context.Context,
	beginner transactionBeginner,
	scope transactionScope,
	accessMode pgx.TxAccessMode,
	callback func(context.Context, transaction) error,
) error {
	if ctx == nil {
		return errors.New("scoped Postgres transaction context is required")
	}
	tx, err := beginner.BeginTx(ctx, pgx.TxOptions{AccessMode: accessMode})
	if err != nil {
		return fmt.Errorf("begin scoped Postgres transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`SELECT set_config($1, $2, true), set_config($3, $4, true)`,
		scope.tenantSetting, scope.tenantID, scope.userSetting, scope.userID,
	); err != nil {
		return fmt.Errorf("install Postgres transaction scope: %w", err)
	}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit scoped Postgres transaction: %w", err)
	}
	return nil
}

func validateSettingName(setting string) error {
	segments := strings.Split(setting, ".")
	if len(segments) < 2 {
		return fmt.Errorf("setting %q must contain a namespace", setting)
	}
	for _, segment := range segments {
		if segment == "" {
			return fmt.Errorf("setting %q contains an empty namespace segment", setting)
		}
		for _, character := range segment {
			if character == '_' ||
				(character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') {
				continue
			}
			return fmt.Errorf("setting %q contains an unsafe character", setting)
		}
	}
	return nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
