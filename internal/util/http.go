package util

import (
	"context"
	"encoding/json"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog"
	"io"
	"net/http"
	"tailscale.com/smallzstd"
)

// HandlerFunc takes care of boilerplate details around handling requests and responses.
type HandlerFunc[I any, O any] func(context.Context, I) (*O, error)

func (h HandlerFunc[I, O]) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	log := zerolog.Ctx(req.Context())

	var input I
	if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
		log.Error().Err(err).Msg("failed to decode request body")
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	out, err := h(req.Context(), input)
	if err != nil {
		log.Error().Err(err).Send()
		http.Error(res, err.Error(), http.StatusBadRequest) // to keep things simple we just assume it to be a client error

		return
	}

	if err = json.NewEncoder(res).Encode(out); err != nil {
		log.Error().Err(err).Msg("failed to encode response body")
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}
}

// StreamingHandlerFunc takes care of boilerplate details around handling requests where
// responses can be sent as a stream of 0 or more objects. It exposes the http.ResponseWriter to the implementer.
type StreamingHandlerFunc[I any] func(context.Context, http.ResponseWriter, I) error

func (h StreamingHandlerFunc[I]) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	log := zerolog.Ctx(req.Context())

	var input I
	if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
		log.Error().Err(err).Msg("failed to decode request body")
		http.Error(res, err.Error(), http.StatusInternalServerError)

		return
	}

	if err := h(req.Context(), res, input); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest) // to keep things simple we just assume it to be a client error
	}
}

// Json encodes the given source object using encoding/json to the given sink.
func Json[T any](src *T, sink io.Writer) error {
	return json.NewEncoder(sink).Encode(src)
}

// Zstd encodes the given source object using encoding/json and compresses using zstd before writing to given sink.
func Zstd[T any](src *T, sink io.Writer) error {
	compressor, err := smallzstd.NewEncoder(sink, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return err
	}

	if err = json.NewEncoder(compressor).Encode(src); err != nil {
		_ = compressor.Close()
		return err
	}

	return compressor.Close()
}
