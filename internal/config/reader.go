package config

import (
	"encoding"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"reflect"
	"strconv"
	"strings"
)

// Read reads configuration values into the provided struct type using Viper and reflection.
func Read[T any]() *T {
	// used below to check if a custom type implements encoding.TextUnmarshaler
	textUnmarshal := reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	binaryUnmarshal := reflect.TypeOf((*encoding.BinaryUnmarshaler)(nil)).Elem()

	var decodeField func(value reflect.Value, field reflect.StructField)
	decodeField = func(value reflect.Value, field reflect.StructField) {
		if key, ok := field.Tag.Lookup("viper"); ok || (!ok && (value.Kind() == reflect.Struct || value.Kind() == reflect.Ptr)) {
			// For types that implement encoding.TextUnmarshaler or encoding.BinaryUnmarshaler,
			// we delegate parsing to UnmarshalText() or UnmarshalBinary() function of the type.
			if ok && (value.Addr().Type().Implements(textUnmarshal) || value.Addr().Type().Implements(binaryUnmarshal)) {
				txt := viper.GetString(key)
				if def, exists := field.Tag.Lookup("default"); (!viper.IsSet(key) || len(txt) == 0) && exists {
					txt = def
				}

				if tm, ok := value.Addr().Interface().(encoding.TextUnmarshaler); ok {
					_ = tm.UnmarshalText([]byte(txt))
				} else if bm, ok := value.Addr().Interface().(encoding.BinaryUnmarshaler); ok {
					_ = bm.UnmarshalBinary([]byte(txt))
				}

				return
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
				if ok {
					value.Set(reflect.ValueOf(viper.Get(key)))
				} else {
					for j := 0; j < value.NumField(); j++ {
						if nestedField := value.Field(j); nestedField.CanSet() {
							decodeField(nestedField, value.Type().Field(j))
						}
					}
				}

			case reflect.Slice:
				for i := 0; i < value.Len(); i++ {
					decodeField(value.Index(i), field)
				}

				// Handle slice of strings, integers, and floats, separated by comma
				if def, exists := field.Tag.Lookup("default"); exists && value.Len() == 0 {
					var defValues []reflect.Value
					sliceType := value.Type().Elem().Kind()

					for _, s := range strings.Split(def, ",") {
						switch sliceType {
						case reflect.String:
							defValues = append(defValues, reflect.ValueOf(s))
						case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
							if v, err := strconv.ParseInt(s, 10, 64); err == nil {
								defValues = append(defValues, reflect.ValueOf(v).Convert(value.Type().Elem()))
							}
						case reflect.Bool:
							if v, err := strconv.ParseBool(s); err == nil {
								defValues = append(defValues, reflect.ValueOf(v))
							}
						case reflect.Float32, reflect.Float64:
							if v, err := strconv.ParseFloat(s, 64); err == nil {
								defValues = append(defValues, reflect.ValueOf(v).Convert(value.Type().Elem()))
							}
						}
					}

					newSlice := reflect.MakeSlice(value.Type(), len(defValues), len(defValues))
					for i := 0; i < len(defValues); i++ {
						newSlice.Index(i).Set(defValues[i])
					}
					value.Set(newSlice)
				}

			case reflect.Ptr:
				if value.IsNil() { // allocate a new object of the appropriate type
					value.Set(reflect.New(value.Type().Elem()))
				}

				decodeField(value.Elem(), field)

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
