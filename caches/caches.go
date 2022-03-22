package caches

import (
	"errors"
	"github.com/ReneKroon/ttlcache"
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
	cache.SkipTtlExtensionOnHit(true)
	//cache.SetCacheSizeLimit(config.MaxItems)
	cache.SetTTL(4 * time.Hour) // Default CrowdSec duration. Set as fallback, should never be used.
	//if err != nil {
	//	return nil, err
	//}

	return &LocalCache{
		cache: cache,
	}, nil
}

func (localCache LocalCache) SetDecision(ip string, isAuthorized bool, expiration time.Duration) (err error) {
	localCache.cache.SetWithTTL(ip, isAuthorized, expiration)
	// TODO handle custom error
	return nil
}

func (localCache LocalCache) GetDecision(ip string) (bool, error) {
	cacheValue, cacheHit := localCache.cache.Get(ip)
	if !cacheHit {
		return false, errors.New("cache miss") // TODO factorize custom error
	}

	isAuthorized, castSucceed := cacheValue.(bool)
	if !castSucceed {
		return false, errors.New("cache result cast fail") // TODO factorize custom error
	}

	return isAuthorized, nil
}
