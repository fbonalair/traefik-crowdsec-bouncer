package main

import (
	"github.com/diegobernardes/ttlcache"
	"time"
)

type DecisionCacheConfig struct {
	MaxItems  int
	MaxMemory int
}

// TODO abstract errors
type DecisionsCache interface {
	SetDecision(ip string, isAuthorized bool, expiration time.Duration) error
	GetDecision(ip string) (*bool, error)
}

type LocalCache struct {
	cache *ttlcache.Cache
}

func NewLocalCache(config DecisionCacheConfig) (*LocalCache, error) {
	cache := ttlcache.NewCache()
	cache.SkipTTLExtensionOnHit(true)
	cache.SetCacheSizeLimit(config.MaxItems)
	err := cache.SetTTL(4 * time.Hour) // Default CrowdSec duration. Set as fallback, should never be used.
	if err != nil {
		return nil, err
	}

	return &LocalCache{
		cache: cache,
	}, nil
}

func (localCache LocalCache) SetDecision(ip string, isAuthorized bool, expiration time.Duration) (err error) {
	err = localCache.cache.SetWithTTL(ip, isAuthorized, expiration)
	// TODO handle custom error
	return
}

func (localCache LocalCache) GetDecision(ip string) (bool, error) {
	cacheValue, err := localCache.cache.Get(ip)
	if err != nil {
		return false, err // TODO custom error
	}

	isAuthorized, castSucceed := cacheValue.(bool)
	if !castSucceed {
		return false, err // TODO custom error
	}

	return isAuthorized, nil
}
