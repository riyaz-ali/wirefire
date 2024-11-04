package oidc

import (
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/errors"
	"github.com/riyaz-ali/wirefire/internal/util"
	"golang.org/x/oauth2"
)

// RemoteService encapsulates oauth2 and oidc exchanger and verifier.
type RemoteService struct {
	provider *oidc.Provider
	config   *oauth2.Config
}

func NewRemoteService(ctx context.Context, cfg *Config) *RemoteService {
	provider := util.Must(oidc.NewProvider(ctx, cfg.Provider))

	return &RemoteService{
		provider: provider,
		config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.BaseUrl.JoinPath("/oidc/callback").String(),
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
	}
}

func (a *RemoteService) AuthCodeURL(state string, options ...oauth2.AuthCodeOption) string {
	return a.config.AuthCodeURL(state, options...)
}

func (a *RemoteService) Exchange(ctx context.Context, code string) (_ string, err error) {
	var token *oauth2.Token
	if token, err = a.config.Exchange(ctx, code); err != nil {
		return "", err
	}

	var raw string
	if raw = token.Extra("id_token").(string); raw == "" {
		return "", errors.New("id_token is empty")
	}

	return raw, nil
}

func (a *RemoteService) Verify(ctx context.Context, token string) (_ *oidc.IDToken, err error) {
	var verifier = a.provider.Verifier(&oidc.Config{ClientID: a.config.ClientID})
	return verifier.Verify(ctx, token)
}
