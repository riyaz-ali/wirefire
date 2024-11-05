package database_test

import (
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"github.com/riyaz-ali/wirefire/internal/database"
	"github.com/riyaz-ali/wirefire/internal/util"
	"net/url"
	"testing"
	"time"
)

func TestScanAs_PrimitiveType(t *testing.T) {
	var conn = util.Must(sqlite.OpenConn("file:memory:?mode=memory", 0))
	defer conn.Close()

	t.Run("ScanAs_Int", func(t *testing.T) {
		type IntTest struct {
			Int   int64     `db:"a"`
			Float float64   `db:"b"`
			Str   string    `db:"c"`
			Time  time.Time `db:"d"`
			Bool  bool      `db:"e"`
		}

		if err := sqlitex.Exec(conn, "CREATE TABLE int_test (a, b, c, d, e)", nil); err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		i := database.I[database.EmptyResponse, IntTest]{
			QueryStr: "INSERT INTO int_test (a, b, c, d, e) VALUES (?1, ?2, ?3, ?4, ?5)",
			ArgSet: []IntTest{
				{Int: 1, Time: time.Now()},
				{Int: 2, Time: time.Now()},
				{Int: 3, Time: time.Now()},
				{Int: 4, Time: time.Now()},
				{Int: 5, Time: time.Now()},
			},
			Bind: func(stmt *sqlite.Stmt, i IntTest) error {
				stmt.BindInt64(1, i.Int)
				stmt.BindInt64(2, i.Int)
				stmt.BindInt64(3, i.Int)
				stmt.BindInt64(4, i.Time.Unix())
				stmt.BindBool(5, i.Int%2 == 0)
				return nil
			},
		}

		if _, err := database.Exec(conn, i); err != nil {
			t.Fatalf("failed to insert records: %v", err)
		}

		q := database.Q[IntTest]{
			QueryStr: "SELECT * FROM int_test",
			Val: func(stmt *sqlite.Stmt) (*IntTest, error) {
				return database.ScanAs[IntTest](stmt)
			},
		}

		res, err := database.FetchMany(conn, q)
		if err != nil {
			t.Fatalf("failed to fetch records: %v", err)
		}

		for _, r := range res {
			t.Logf("%+v\n", r)
		}
	})

	t.Run("ScanAs_Float", func(t *testing.T) {
		type FloatTest struct {
			Float float64   `db:"a"`
			Str   string    `db:"b"`
			Time  time.Time `db:"c"`
			Bool  bool      `db:"d"`
		}

		if err := sqlitex.Exec(conn, "CREATE TABLE float_test (a, b, c, d)", nil); err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		i := database.I[database.EmptyResponse, FloatTest]{
			QueryStr: "INSERT INTO float_test (a, b, c, d) VALUES (?1, ?2, ?3, ?4)",
			ArgSet: []FloatTest{
				{Float: 1.1, Time: time.Now()},
				{Float: 2.1, Time: time.Now()},
				{Float: 3.1, Time: time.Now()},
				{Float: 4.1, Time: time.Now()},
				{Float: 5.1, Time: time.Now()},
			},
			Bind: func(stmt *sqlite.Stmt, i FloatTest) error {
				stmt.BindFloat(1, i.Float)
				stmt.BindFloat(2, i.Float)
				stmt.BindFloat(3, float64(i.Time.Unix()))
				stmt.BindFloat(4, float64(int(i.Float)%2))
				return nil
			},
		}

		if _, err := database.Exec(conn, i); err != nil {
			t.Fatalf("failed to insert records: %v", err)
		}

		q := database.Q[FloatTest]{
			QueryStr: "SELECT * FROM float_test",
			Val: func(stmt *sqlite.Stmt) (*FloatTest, error) {
				return database.ScanAs[FloatTest](stmt)
			},
		}

		res, err := database.FetchMany(conn, q)
		if err != nil {
			t.Fatalf("failed to fetch records: %v", err)
		}

		for _, r := range res {
			t.Logf("%+v\n", r)
		}
	})

	t.Run("ScanAs_Str", func(t *testing.T) {
		type StrTest struct {
			Str  string `db:"a"`
			Blob []byte `db:"b"`
		}

		if err := sqlitex.Exec(conn, "CREATE TABLE string_test (a, b)", nil); err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		i := database.I[database.EmptyResponse, StrTest]{
			QueryStr: "INSERT INTO string_test (a, b) VALUES (?1, ?2)",
			ArgSet: []StrTest{
				{Str: "example text"},
				{Str: "another example"},
				{Str: "more sample text"},
				{Str: "text for testing"},
				{Str: "additional text"},
				{Str: "final example"},
			},
			Bind: func(stmt *sqlite.Stmt, i StrTest) error {
				stmt.BindText(1, i.Str)
				stmt.BindText(2, hex.EncodeToString([]byte(i.Str)))
				return nil
			},
		}

		if _, err := database.Exec(conn, i); err != nil {
			t.Fatalf("failed to insert records: %v", err)
		}

		q := database.Q[StrTest]{
			QueryStr: "SELECT * FROM string_test",
			Val: func(stmt *sqlite.Stmt) (*StrTest, error) {
				return database.ScanAs[StrTest](stmt)
			},
		}

		res, err := database.FetchMany(conn, q)
		if err != nil {
			t.Fatalf("failed to fetch records: %v", err)
		}

		for _, r := range res {
			t.Logf("%+v\n", r)
		}
	})

	t.Run("ScanAs_Blob", func(t *testing.T) {
		type BlobTest struct {
			Str  string `db:"a"`
			Blob []byte `db:"b"`
		}

		if err := sqlitex.Exec(conn, "CREATE TABLE blob_test (a, b)", nil); err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		i := database.I[database.EmptyResponse, BlobTest]{
			QueryStr: "INSERT INTO blob_test (a, b) VALUES (?1, ?2)",
			ArgSet: []BlobTest{
				{Str: "example text"},
				{Str: "another example"},
				{Str: "more sample text"},
				{Str: "text for testing"},
				{Str: "additional text"},
				{Str: "final example"},
			},
			Bind: func(stmt *sqlite.Stmt, i BlobTest) error {
				stmt.BindBytes(1, []byte(i.Str))
				stmt.BindBytes(2, []byte(hex.EncodeToString([]byte(i.Str))))
				return nil
			},
		}

		if _, err := database.Exec(conn, i); err != nil {
			t.Fatalf("failed to insert records: %v", err)
		}

		q := database.Q[BlobTest]{
			QueryStr: "SELECT * FROM blob_test",
			Val: func(stmt *sqlite.Stmt) (*BlobTest, error) {
				return database.ScanAs[BlobTest](stmt)
			},
		}

		res, err := database.FetchMany(conn, q)
		if err != nil {
			t.Fatalf("failed to fetch records: %v", err)
		}

		for _, r := range res {
			t.Logf("%+v\n", r)
		}
	})
}

type Scanable struct{ V int }

func (s *Scanable) Scan(src any) error {
	if s == nil {
		return errors.New("scanable: nil pointer")
	}

	if str, ok := src.([]byte); ok {
		_, _ = fmt.Sscanf(string(str), "%d", &s.V)
		return nil
	} else {
		return errors.Errorf("scanable: invalid type %T", src)
	}
}

func TestScanAs_Scanner(t *testing.T) {
	var conn = util.Must(sqlite.OpenConn("file:memory:?mode=memory", 0))
	defer conn.Close()

	type Result struct{ Scn *Scanable }
	var res *Result

	err := sqlitex.Exec(conn, "SELECT '123' AS Scn", func(stmt *sqlite.Stmt) (err error) {
		res, err = database.ScanAs[Result](stmt)
		return err
	})

	if err != nil {
		t.Fatalf("failed to execute query: %v", err)
	}

	if res == nil || res.Scn.V != 123 {
		t.Fatalf("invalid value: %v", res.Scn)
	}
}

func TestScanAs_Unmarshaler(t *testing.T) {
	var conn = util.Must(sqlite.OpenConn("file:memory:?mode=memory", 0))
	defer conn.Close()

	t.Run("TextAndBinaryUnmarshaler", func(t *testing.T) {
		type Result struct {
			Url  *url.URL  `json:"url,omitempty"` // implements BinaryUnmarshaler, also tests Pointer type
			Url2 *url.URL  `json:"-"`             // test for SQLITE_NULL
			Time time.Time `json:"time"`          // implements TextUnmarshaler
		}

		var res *Result
		err := sqlitex.Exec(conn, "SELECT 'https://google.com' AS Url, NULL AS Url2, '2024-01-01T00:00:00+05:30' AS Time", func(stmt *sqlite.Stmt) (err error) {
			res, err = database.ScanAs[Result](stmt)
			return err
		})

		if err != nil {
			t.Fatalf("failed to execute query: %v", err)
		}

		if res == nil || res.Url.String() != "https://google.com" || res.Url2 != nil || res.Time.IsZero() {
			t.Fatalf("invalid value: %v", res)
		}
	})

	t.Run("JsonUnmarshaler", func(t *testing.T) {
		type Result struct {
			M map[string]string `db:"m,json"`
		}

		var res *Result
		err := sqlitex.Exec(conn, "SELECT json_object('a', 'one', 'b', 'two') AS m", func(stmt *sqlite.Stmt) (err error) {
			res, err = database.ScanAs[Result](stmt)
			return err
		})

		if err != nil {
			t.Fatalf("failed to execute query: %v", err)
		}

		if res == nil || len(res.M) == 0 || res.M["a"] != "one" {
			t.Fatalf("invalid value: %v", res)
		}
	})
}

type AliasStr string

const (
	AliasA = AliasStr("a")
	AliasB = AliasStr("b")
)

type AliasInt int

const (
	_ = iota
	AliasIntA
	AliasIntB
)

func TestScanAs_Alias(t *testing.T) {
	var conn = util.Must(sqlite.OpenConn("file:memory:?mode=memory", 0))
	defer conn.Close()

	type Result struct {
		S AliasStr
		I AliasInt
	}

	var res *Result
	err := sqlitex.Exec(conn, "SELECT 'a' AS S, 2 AS I", func(stmt *sqlite.Stmt) (err error) {
		res, err = database.ScanAs[Result](stmt)
		return err
	})

	if err != nil {
		t.Fatalf("failed to execute query: %v", err)
	}

	if res == nil || res.S != AliasA || res.I != AliasIntB {
		t.Fatalf("invalid value: %v", res)
	}
}
