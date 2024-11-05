package database

import (
	"crawshaw.io/sqlite"
	"database/sql"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// ScanAs scans and return the value T from the given sqlite.Stmt, using reflection for mapping.
func ScanAs[T any](stmt *sqlite.Stmt) (*T, error) {
	type FieldInfo struct {
		Field reflect.Value
		Json  bool
	}

	var dest T
	var fields = make(map[string]FieldInfo)
	for i, val := 0, reflect.ValueOf(&dest).Elem(); i < val.NumField(); i++ {
		name := val.Type().Field(i).Name
		if tag, exists := val.Type().Field(i).Tag.Lookup("db"); exists {
			if tag != "-" {
				parts := strings.SplitN(tag, ",", 2)
				name = parts[0]
				if len(parts) > 1 {
					fields[name] = FieldInfo{Field: val.Field(i), Json: parts[1] == "json"}
				} else {
					fields[name] = FieldInfo{Field: val.Field(i)}
				}
			}
		} else {
			fields[name] = FieldInfo{Field: val.Field(i)}
		}
	}

	for i := 0; i < stmt.ColumnCount(); i++ {
		field := fields[stmt.ColumnName(i)]
		if !field.Field.IsValid() {
			return nil, fmt.Errorf("no field found for %q", stmt.ColumnName(i))
		}

		if err := scan(stmt, i, field.Field, field.Json); err != nil {
			return nil, err
		}
	}

	return &dest, nil
}

func scan(stmt *sqlite.Stmt, i int, value reflect.Value, useJson bool) error {
	columnType := stmt.ColumnType(i)

	switch columnType {
	case sqlite.SQLITE_INTEGER:
		switch value.Interface().(type) {
		case int, int8, int16, int32, int64:
			value.SetInt(stmt.ColumnInt64(i))
			return nil

		case float32, float64:
			value.SetFloat(float64(stmt.ColumnInt64(i)))
			return nil

		case string:
			value.SetString(strconv.FormatInt(stmt.ColumnInt64(i), 10))
			return nil

		case time.Time:
			value.Set(reflect.ValueOf(time.Unix(stmt.ColumnInt64(i), 0)))
			return nil

		case bool:
			value.SetBool(stmt.ColumnInt(i) != 0)
			return nil
		}

	case sqlite.SQLITE_FLOAT:
		switch value.Interface().(type) {
		case float64:
			value.SetFloat(stmt.ColumnFloat(i))
			return nil

		case string:
			value.SetString(strconv.FormatFloat(stmt.ColumnFloat(i), 'f', -1, 64))
			return nil

		case time.Time:
			value.Set(reflect.ValueOf(time.Unix(0, int64(stmt.ColumnFloat(i)*float64(time.Second)))))
			return nil

		case bool:
			value.SetBool(stmt.ColumnFloat(i) != 0)
			return nil

		}

	case sqlite.SQLITE_TEXT:
		switch value.Interface().(type) {
		case string:
			value.SetString(stmt.ColumnText(i))
			return nil

		case []byte:
			var buf = make([]byte, stmt.ColumnLen(i)) // allocate a buffer
			stmt.ColumnBytes(i, buf)
			value.SetBytes(buf)

			return nil
		}

	case sqlite.SQLITE_BLOB:
		switch value.Interface().(type) {
		case string:
			value.SetString(stmt.ColumnText(i))
			return nil

		case []byte:
			var buf = make([]byte, stmt.ColumnLen(i)) // allocate a buffer
			stmt.ColumnBytes(i, buf)
			value.SetBytes(buf)

			return nil
		}
	}

	// for types that support database/sql.Scanner interface
	if scanner, ok := value.Addr().Interface().(sql.Scanner); ok {
		var buf = make([]byte, stmt.ColumnLen(i))
		stmt.ColumnBytes(i, buf)

		return scanner.Scan(buf)
	}

	if columnType == sqlite.SQLITE_TEXT || columnType == sqlite.SQLITE_BLOB {
		if tum, ok := value.Addr().Interface().(encoding.TextUnmarshaler); ok {
			var buf = make([]byte, stmt.ColumnLen(i))
			stmt.ColumnBytes(i, buf)

			return tum.UnmarshalText(buf)
		} else if bum, ok := value.Addr().Interface().(encoding.BinaryUnmarshaler); ok {
			var buf = make([]byte, stmt.ColumnLen(i))
			stmt.ColumnBytes(i, buf)

			return bum.UnmarshalBinary(buf)
		}

	}

	// The following conversions use a string value as an intermediate representation
	// to convert between various numeric types.
	//
	// This also allows scanning into user defined types such as "type Int int64".
	// For symmetry, also check for string destination types.
	src := stmt.ColumnText(i)

	switch value.Kind() {
	case reflect.Pointer:
		if columnType == sqlite.SQLITE_NULL || src == "" {
			value.Set(reflect.Zero(value.Type())) // set to nil pointer
			return nil
		} else {
			if value.IsNil() { // allocate value for pointer
				value.Set(reflect.New(value.Type().Elem()))
			}

			return scan(stmt, i, reflect.Indirect(value), useJson)
		}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if columnType == sqlite.SQLITE_NULL || src == "" {
			return fmt.Errorf("failed to convert null to a %s", value.Kind())
		}

		i64, err := strconv.ParseInt(src, 10, value.Type().Bits())
		if err != nil {
			return fmt.Errorf("failed to convert string to a %s: %v", value.Kind(), err)
		}
		value.SetInt(i64)
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if columnType == sqlite.SQLITE_NULL || src == "" {
			return fmt.Errorf("failed to convert null to a %s", value.Kind())
		}

		u64, err := strconv.ParseUint(src, 10, value.Type().Bits())
		if err != nil {
			return fmt.Errorf("failed to convert string to a %s: %v", value.Kind(), err)
		}
		value.SetUint(u64)
		return nil

	case reflect.Float32, reflect.Float64:
		if columnType == sqlite.SQLITE_NULL || src == "" {
			return fmt.Errorf("failed to convert null to a %s", value.Kind())
		}

		f64, err := strconv.ParseFloat(src, value.Type().Bits())
		if err != nil {
			return fmt.Errorf("failed to convert string to a %s: %v", value.Kind(), err)
		}
		value.SetFloat(f64)
		return nil

	case reflect.String:
		value.SetString(src)
		return nil
	}

	if useJson { // if useJson is set, we use encoding/json to un-marshal sqlite result (read as a blob) into destination
		buf := stmt.ColumnReader(i)
		return json.NewDecoder(buf).Decode(value.Addr().Interface())
	}

	return fmt.Errorf("unsupported destination type %s for column %s", value.Type().Name(), stmt.ColumnName(i))
}
