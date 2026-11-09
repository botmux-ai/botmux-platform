package store

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// NewMongoDatabaseProvider connects to MongoDB with the official driver.
// Dial failures are retried every 30s.
func NewMongoDatabaseProvider(uri, database string) *RetryingDatabaseProvider {
	return &RetryingDatabaseProvider{
		RetryDelay: 30 * time.Second,
		Dial: func(ctx context.Context) (DocumentDatabase, io.Closer, error) {
			client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri).
				SetServerSelectionTimeout(3*time.Second).
				SetConnectTimeout(3*time.Second))
			if err != nil {
				slog.Warn("runtime dependency failure", "dependency", "mongodb", "operation", "connect", "error", err)
				return nil, nil, err
			}
			// mongo.Connect only starts topology-monitoring goroutines; it does
			// not perform network I/O. Ping makes an unavailable cluster
			// enter RetryingDatabaseProvider's backoff instead of caching a client
			// whose every operation immediately fails.
			if err := client.Ping(ctx, nil); err != nil {
				_ = mongoCloser{client: client}.Close()
				slog.Warn("runtime dependency failure", "dependency", "mongodb", "operation", "ping", "error", err)
				return nil, nil, err
			}
			return mongoDatabase{db: client.Database(database)}, mongoCloser{client: client}, nil
		},
	}
}

type mongoCloser struct{ client *mongo.Client }

func (c mongoCloser) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.client.Disconnect(ctx)
}

type mongoDatabase struct{ db *mongo.Database }

func (d mongoDatabase) Collection(name string) DocumentCollection {
	return mongoCollection{name: name, collection: d.db.Collection(name)}
}

type mongoCollection struct {
	name       string
	collection *mongo.Collection
}

func (c mongoCollection) CreateIndex(ctx context.Context, keys Document) error {
	_, err := c.collection.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: ToBSON(keys)})
	return c.observe("create_index", err)
}
func (c mongoCollection) CreateIndexSpec(ctx context.Context, spec IndexSpec) error {
	opts := options.Index()
	if spec.Unique {
		opts.SetUnique(true)
	}
	if spec.ExpireAfterSeconds != nil {
		opts.SetExpireAfterSeconds(*spec.ExpireAfterSeconds)
	}
	_, err := c.collection.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: orderedKeys(spec.Keys), Options: opts})
	return c.observe("create_index", err)
}
func (c mongoCollection) InsertOne(ctx context.Context, value any) error {
	if document, ok := value.(Document); ok {
		value = ToBSON(document)
	}
	_, err := c.collection.InsertOne(ctx, value)
	return c.observe("insert_one", err)
}
func (c mongoCollection) FindOne(ctx context.Context, filter Document, dst any) error {
	return c.observe("find_one", c.collection.FindOne(ctx, ToBSON(filter)).Decode(dst))
}
func (c mongoCollection) FindMany(ctx context.Context, filter Document, dst any) error {
	cursor, err := c.collection.Find(ctx, ToBSON(filter))
	if err != nil {
		return c.observe("find_many", err)
	}
	defer cursor.Close(ctx)
	return c.observe("find_many_decode", cursor.All(ctx, dst))
}
func (c mongoCollection) FindManyOptions(ctx context.Context, filter Document, opts FindOptions, dst any) error {
	findOpts := options.Find()
	if len(opts.Sort) > 0 {
		findOpts.SetSort(orderedKeys(opts.Sort))
	}
	if opts.Limit > 0 {
		findOpts.SetLimit(opts.Limit)
	}
	cursor, err := c.collection.Find(ctx, ToBSON(filter), findOpts)
	if err != nil {
		return c.observe("find_many", err)
	}
	defer cursor.Close(ctx)
	return c.observe("find_many_decode", cursor.All(ctx, dst))
}
func (c mongoCollection) FindOneAndUpdate(ctx context.Context, filter, update Document, opts FindOneAndUpdateOptions, dst any) error {
	updateOpts := options.FindOneAndUpdate().SetUpsert(opts.Upsert).SetReturnDocument(options.Before)
	if opts.ReturnAfter {
		updateOpts.SetReturnDocument(options.After)
	}
	result := c.collection.FindOneAndUpdate(ctx, ToBSON(filter), ToBSON(update), updateOpts)
	if dst == nil {
		return c.observe("find_one_and_update", result.Err())
	}
	return c.observe("find_one_and_update", result.Decode(dst))
}
func (c mongoCollection) UpdateOne(ctx context.Context, filter, update Document, upsert bool) (UpdateResult, error) {
	r, err := c.collection.UpdateOne(ctx, ToBSON(filter), ToBSON(update), options.Update().SetUpsert(upsert))
	if err != nil {
		return UpdateResult{}, c.observe("update_one", err)
	}
	upserted := int64(0)
	if r.UpsertedID != nil {
		upserted = 1
	}
	return UpdateResult{Matched: r.MatchedCount, Modified: r.ModifiedCount, Upserted: upserted}, nil
}
func (c mongoCollection) UpdateMany(ctx context.Context, filter, update Document) (UpdateResult, error) {
	r, err := c.collection.UpdateMany(ctx, ToBSON(filter), ToBSON(update))
	if err != nil {
		return UpdateResult{}, c.observe("update_many", err)
	}
	return UpdateResult{Matched: r.MatchedCount, Modified: r.ModifiedCount}, nil
}
func (c mongoCollection) DeleteOne(ctx context.Context, filter Document) (DeleteResult, error) {
	r, err := c.collection.DeleteOne(ctx, ToBSON(filter))
	if err != nil {
		return DeleteResult{}, c.observe("delete_one", err)
	}
	return DeleteResult{Deleted: r.DeletedCount}, nil
}

func (c mongoCollection) DeleteMany(ctx context.Context, filter Document) (DeleteResult, error) {
	r, err := c.collection.DeleteMany(ctx, ToBSON(filter))
	if err != nil {
		return DeleteResult{}, c.observe("delete_many", err)
	}
	return DeleteResult{Deleted: r.DeletedCount}, nil
}

func orderedKeys(keys []IndexKey) bson.D {
	out := make(bson.D, 0, len(keys))
	for _, key := range keys {
		out = append(out, bson.E{Key: key.Field, Value: key.Order})
	}
	return out
}

func (c mongoCollection) observe(operation string, err error) error {
	err = normalizeMongoError(err)
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) && !errors.Is(err, context.Canceled) {
		slog.Warn("runtime dependency failure", "dependency", "mongodb", "operation", operation, "collection", c.name, "error", err)
	}
	return err
}

// ToBSON converts a Document, including nested Documents, into bson.M.
func ToBSON(in Document) bson.M {
	out := make(bson.M, len(in))
	for key, value := range in {
		out[key] = bsonValue(value)
	}
	return out
}
func bsonValue(value any) any {
	switch v := value.(type) {
	case Document:
		return ToBSON(v)
	case []Document:
		out := make([]bson.M, len(v))
		for i := range v {
			out[i] = ToBSON(v[i])
		}
		return out
	default:
		return value
	}
}
func normalizeMongoError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return ErrNotFound
	}
	if mongo.IsDuplicateKeyError(err) {
		return ErrConflict
	}
	return err
}

var _ DocumentDatabase = mongoDatabase{}
var _ DocumentCollection = mongoCollection{}
