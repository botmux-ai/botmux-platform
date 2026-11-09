package store

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisFactory opens the coordination store on Redis. KVConfig.Address is a
// redis:// or rediss:// URL (see redis.ParseURL). Keys keep their explicit
// [table] prefix, so several deployments can share one Redis database.
type RedisFactory struct{}

func (RedisFactory) Open(ctx context.Context, cfg KVConfig) (KVClient, io.Closer, error) {
	options, err := redis.ParseURL(cfg.Address)
	if err != nil {
		// The URL may carry a password; never log or wrap it verbatim.
		slog.Warn("runtime dependency failure", "dependency", "redis", "operation", "parse_url", "error", "invalid REDIS_URL")
		return nil, nil, errors.New("invalid REDIS_URL")
	}
	client := redis.NewClient(options)
	probeErr := client.Get(ctx, "["+cfg.Table+"]__botmux_probe__").Err()
	if probeErr != nil && !errors.Is(probeErr, redis.Nil) {
		_ = client.Close()
		slog.Warn("runtime dependency failure", "dependency", "redis", "operation", "probe", "error", probeErr)
		return nil, nil, probeErr
	}
	return &redisKV{client: client}, client, nil
}

type redisKV struct{ client *redis.Client }

func (r *redisKV) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return observeRedis("set", r.client.Set(ctx, key, value, ttl).Err())
}

func (r *redisKV) Get(ctx context.Context, key string) (string, error) {
	value, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrKeyNotFound
	}
	return value, observeRedis("get", err)
}

func (r *redisKV) Delete(ctx context.Context, key string) error {
	return observeRedis("delete", r.client.Del(ctx, key).Err())
}

// compareAndDeleteScript deletes KEYS[1] only while it equals ARGV[1], so a
// route rewritten by its new owner can never be removed by the previous one.
var compareAndDeleteScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0`)

func (r *redisKV) CompareAndDelete(ctx context.Context, key, expected string) (bool, error) {
	deleted, err := compareAndDeleteScript.Run(ctx, r.client, []string{key}, expected).Int64()
	if err != nil {
		return false, observeRedis("compare_and_delete", err)
	}
	return deleted == 1, nil
}

func observeRedis(operation string, err error) error {
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrKeyNotFound) {
		slog.Warn("runtime dependency failure", "dependency", "redis", "operation", operation, "error", err)
	}
	return err
}

var _ KVClientFactory = RedisFactory{}
var _ KVClient = (*redisKV)(nil)
