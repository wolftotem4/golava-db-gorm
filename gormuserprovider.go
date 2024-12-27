package gorm

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/wolftotem4/golava-core/auth"
	"github.com/wolftotem4/golava-core/hashing"
	"gorm.io/gorm"
)

type GormUserProvider struct {
	DB            *gorm.DB
	Hasher        hashing.Hasher
	ConstructUser func() auth.Authenticatable
}

func (p *GormUserProvider) RetrieveById(ctx context.Context, identifier any) (auth.Authenticatable, error) {
	user := p.ConstructUser()
	result := p.DB.First(user, identifier)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, auth.ErrUserNotFound
	}
	return user, result.Error
}

func (p *GormUserProvider) RetrieveByToken(ctx context.Context, identifier any, token string) (auth.Authenticatable, error) {
	user := p.ConstructUser()
	result := p.DB.First(user, identifier)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, auth.ErrUserNotFound
	} else if result.Error != nil {
		return nil, result.Error
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(user.GetRememberToken())) != 1 {
		return nil, auth.ErrUserNotFound
	}

	return user, nil
}

func (p *GormUserProvider) UpdateRememberToken(ctx context.Context, user auth.Authenticatable, token string) error {
	return p.DB.Model(user).Update(user.GetRememberTokenName(), token).Error
}

func (p *GormUserProvider) RetrieveByCredentials(ctx context.Context, credentials map[string]any) (auth.Authenticatable, error) {
	var excludePassword = make(map[string]any)
	for key, value := range credentials {
		if !strings.Contains(key, "password") {
			excludePassword[key] = value
		}
	}

	if len(excludePassword) == 0 {
		return nil, auth.ErrUserNotFound
	}

	user := p.ConstructUser()
	result := p.DB.Where(excludePassword).First(user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, auth.ErrUserNotFound
	}
	return user, result.Error
}

func (p *GormUserProvider) ValidateCredentials(ctx context.Context, user auth.Authenticatable, credentials map[string]any) (bool, error) {
	password, ok := credentials[user.GetAuthPasswordName()]
	if !ok {
		return false, nil
	}

	return p.Hasher.Check(password.(string), user.GetAuthPassword())
}

func (p *GormUserProvider) RehashPasswordIfRequired(ctx context.Context, user auth.Authenticatable, credentials map[string]any, force bool) (newhash string, err error) {
	if !p.Hasher.NeedsRehash(user.GetAuthPassword()) && !force {
		return "", nil
	}

	hash, err := p.Hasher.Make(credentials[user.GetAuthPasswordName()].(string))
	if err != nil {
		return "", err
	}

	return hash, p.DB.Model(user).Update(user.GetAuthPasswordName(), hash).Error
}
