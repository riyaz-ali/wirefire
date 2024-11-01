package config

import (
	"encoding"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"reflect"
	"strconv"
)

// Read reads configuration values into the provided struct type using Viper and reflection.
func Read[T any]() *T {
	// used below to check if a custom type implements encoding.TextUnmarshaler
	textUnmarshal := reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()

	var decodeField func(value reflect.Value, field reflect.StructField)
	decodeField = func(value reflect.Value, field reflect.StructField) {
		if key, ok := field.Tag.Lookup("viper"); ok || (!ok && value.Kind() == reflect.Struct /* embedded structs */) {
			// For types that implement encoding.TextUnmarshaler, we delegate parsing to
			// UnmarshalText() function of the type.
			if ok && value.Addr().Type().Implements(textUnmarshal) {
				txt := viper.GetString(key)
				if def, exists := field.Tag.Lookup("default"); (!viper.IsSet(key) || len(txt) == 0) && exists {
					txt = def
				}

				_ = value.Addr().Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(txt))
			}

			switch value.Kind() {
			case reflect.String:
				if viper.IsSet(key) {
					value.SetString(viper.GetString(key))
				} else if def, exists := field.Tag.Lookup("default"); exists {
					value.SetString(def)
				}

			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if viper.IsSet(key) {
					value.SetInt(viper.GetInt64(key))
				} else if def, exists := field.Tag.Lookup("default"); exists {
					if v, err := strconv.ParseInt(def, 10, 64); err == nil {
						value.SetInt(v)
					}
				}
			case reflect.Bool:
				if viper.IsSet(key) {
					value.SetBool(viper.GetBool(key))
				} else if def, exists := field.Tag.Lookup("default"); exists {
					if v, err := strconv.ParseBool(def); err == nil {
						value.SetBool(v)
					}
				}
			case reflect.Float32, reflect.Float64:
				if viper.IsSet(key) {
					value.SetFloat(viper.GetFloat64(key))
				} else if def, exists := field.Tag.Lookup("default"); exists {
					if v, err := strconv.ParseFloat(def, 64); err == nil {
						value.SetFloat(v)
					}
				}
			case reflect.Struct: // to support nested struct config
				for j := 0; j < value.NumField(); j++ {
					if nestedField := value.Field(j); nestedField.CanSet() {
						decodeField(nestedField, value.Type().Field(j))
					}
				}
			default:
				panic(errors.Errorf("unknown type %s", value.Kind()))
			}
		}
	}

	var config T // create a new instance of config type T

	for i, val := 0, reflect.ValueOf(&config).Elem(); i < val.NumField(); i++ {
		if field := val.Field(i); field.CanSet() {
			decodeField(field, val.Type().Field(i))
		}
	}

	return &config
}
