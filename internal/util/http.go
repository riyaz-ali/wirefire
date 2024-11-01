package util

import (
	"context"
	"encoding/json"
	"github.com/rs/zerolog"
	"net/http"
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
