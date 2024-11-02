package config

import (
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Validate applies validation on the config based on struct-tags. It returns
// an error if validation fails.
func Validate[T any](config *T) (*T, error) {
	validate := validator.New(validator.WithRequiredStructEnabled())
	_ = validate.RegisterValidation("loglevel", logLevel)

	return config, validate.Struct(config)
}

// MustValidate applies validation on the config based on struct-tags. It panics
// if the validation check fails.
func MustValidate[T any](config *T) *T {
	if _, err := Validate(config); err != nil {
		log.Fatal().Err(err).Msg("failed to validate config")
	}

	return config
}

func logLevel(fl validator.FieldLevel) bool {
	level, ok := fl.Field().Interface().(zerolog.Level)
	return ok && level != zerolog.NoLevel
}
