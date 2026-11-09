package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// MemoryDatabase is an in-process DocumentDatabase with the Mongo semantics the
// MongoDB repositories rely on. It lets local development, smoke tests and
// unit tests exercise the exact production query/update code instead of a
// parallel hand-written memory implementation.
//
// Values round-trip through the real BSON codec, so struct tags, omitempty and
// numeric BSON types (double vs int32/int64) behave as they do against
// MongoDB. TTL indexes are accepted but never expire documents; callers that
// depend on expiry must also check their expiry field, as the Node service
// does in memory mode.
type MemoryDatabase struct {
	mu          sync.Mutex
	collections map[string]*MemoryCollection
}

func NewMemoryDatabase() *MemoryDatabase {
	return &MemoryDatabase{collections: make(map[string]*MemoryCollection)}
}

// NewMemoryDatabaseProvider returns a provider that is always available.
func NewMemoryDatabaseProvider() StaticDatabaseProvider {
	return StaticDatabaseProvider{DB: NewMemoryDatabase()}
}

func (d *MemoryDatabase) Collection(name string) DocumentCollection {
	return d.MemoryCollection(name)
}

// MemoryCollection exposes the concrete collection for tests that need to
// inspect raw stored documents.
func (d *MemoryDatabase) MemoryCollection(name string) *MemoryCollection {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.collections[name]
	if !ok {
		c = &MemoryCollection{name: name}
		d.collections[name] = c
	}
	return c
}

type MemoryCollection struct {
	name    string
	mu      sync.Mutex
	docs    []map[string]any
	uniques [][]string
}

var errMemoryUnsupported = errors.New("memdoc: unsupported operation")

// Documents returns deep copies of the stored documents in natural order.
func (c *MemoryCollection) Documents() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]map[string]any, len(c.docs))
	for i, doc := range c.docs {
		out[i] = deepCopy(doc).(map[string]any)
	}
	return out
}

func (c *MemoryCollection) CreateIndex(ctx context.Context, keys Document) error {
	return checkContext(ctx)
}

func (c *MemoryCollection) CreateIndexSpec(ctx context.Context, spec IndexSpec) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if !spec.Unique {
		return nil
	}
	fields := make([]string, len(spec.Keys))
	for i, key := range spec.Keys {
		fields[i] = key.Field
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.uniques {
		if reflect.DeepEqual(existing, fields) {
			return nil
		}
	}
	c.uniques = append(c.uniques, fields)
	return nil
}

func (c *MemoryCollection) InsertOne(ctx context.Context, value any) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	doc, err := normalizeDocument(value)
	if err != nil {
		return err
	}
	if _, ok := doc["_id"]; !ok {
		doc["_id"] = primitive.NewObjectID()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkUnique(doc, -1); err != nil {
		return err
	}
	c.docs = append(c.docs, doc)
	return nil
}

func (c *MemoryCollection) FindOne(ctx context.Context, filter Document, dst any) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	f, err := normalizeDocument(filter)
	if err != nil {
		return err
	}
	c.mu.Lock()
	var found map[string]any
	for _, doc := range c.docs {
		if ok, err := matchDocument(doc, f); err != nil {
			c.mu.Unlock()
			return err
		} else if ok {
			found = deepCopy(doc).(map[string]any)
			break
		}
	}
	c.mu.Unlock()
	if found == nil {
		return ErrNotFound
	}
	return decodeInto(found, dst)
}

func (c *MemoryCollection) FindMany(ctx context.Context, filter Document, dst any) error {
	return c.FindManyOptions(ctx, filter, FindOptions{}, dst)
}

func (c *MemoryCollection) FindManyOptions(ctx context.Context, filter Document, opts FindOptions, dst any) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	f, err := normalizeDocument(filter)
	if err != nil {
		return err
	}
	c.mu.Lock()
	var matched []map[string]any
	for _, doc := range c.docs {
		ok, err := matchDocument(doc, f)
		if err != nil {
			c.mu.Unlock()
			return err
		}
		if ok {
			matched = append(matched, deepCopy(doc).(map[string]any))
		}
	}
	c.mu.Unlock()
	if len(opts.Sort) > 0 {
		sort.SliceStable(matched, func(i, j int) bool {
			for _, key := range opts.Sort {
				a, _ := lookupPath(matched[i], key.Field)
				b, _ := lookupPath(matched[j], key.Field)
				cmp := compareForSort(a, b)
				if cmp == 0 {
					continue
				}
				if key.Order < 0 {
					return cmp > 0
				}
				return cmp < 0
			}
			return false
		})
	}
	if opts.Limit > 0 && int64(len(matched)) > opts.Limit {
		matched = matched[:opts.Limit]
	}
	return decodeSliceInto(matched, dst)
}

func (c *MemoryCollection) FindOneAndUpdate(ctx context.Context, filter, update Document, opts FindOneAndUpdateOptions, dst any) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	before, after, _, err := c.updateOne(filter, update, opts.Upsert)
	if err != nil {
		return err
	}
	selected := before
	if opts.ReturnAfter {
		selected = after
	}
	if selected == nil {
		return ErrNotFound
	}
	if dst == nil {
		return nil
	}
	return decodeInto(selected, dst)
}

func (c *MemoryCollection) UpdateOne(ctx context.Context, filter, update Document, upsert bool) (UpdateResult, error) {
	if err := checkContext(ctx); err != nil {
		return UpdateResult{}, err
	}
	_, _, result, err := c.updateOne(filter, update, upsert)
	return result, err
}

func (c *MemoryCollection) updateOne(filter, update Document, upsert bool) (before, after map[string]any, result UpdateResult, err error) {
	f, err := normalizeDocument(filter)
	if err != nil {
		return nil, nil, UpdateResult{}, err
	}
	u, err := normalizeDocument(update)
	if err != nil {
		return nil, nil, UpdateResult{}, err
	}
	if err := validateUpdate(u); err != nil {
		return nil, nil, UpdateResult{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, doc := range c.docs {
		ok, err := matchDocument(doc, f)
		if err != nil {
			return nil, nil, UpdateResult{}, err
		}
		if !ok {
			continue
		}
		next := deepCopy(doc).(map[string]any)
		if err := applyUpdate(next, u, false); err != nil {
			return nil, nil, UpdateResult{}, err
		}
		if err := c.checkUnique(next, i); err != nil {
			return nil, nil, UpdateResult{}, err
		}
		result = UpdateResult{Matched: 1}
		if !reflect.DeepEqual(doc, next) {
			result.Modified = 1
		}
		c.docs[i] = next
		return deepCopy(doc).(map[string]any), deepCopy(next).(map[string]any), result, nil
	}
	if !upsert {
		return nil, nil, UpdateResult{}, nil
	}
	inserted := seedFromFilter(f)
	if err := applyUpdate(inserted, u, true); err != nil {
		return nil, nil, UpdateResult{}, err
	}
	if _, ok := inserted["_id"]; !ok {
		inserted["_id"] = primitive.NewObjectID()
	}
	if err := c.checkUnique(inserted, -1); err != nil {
		return nil, nil, UpdateResult{}, err
	}
	c.docs = append(c.docs, inserted)
	return nil, deepCopy(inserted).(map[string]any), UpdateResult{Upserted: 1}, nil
}

func (c *MemoryCollection) UpdateMany(ctx context.Context, filter, update Document) (UpdateResult, error) {
	if err := checkContext(ctx); err != nil {
		return UpdateResult{}, err
	}
	f, err := normalizeDocument(filter)
	if err != nil {
		return UpdateResult{}, err
	}
	u, err := normalizeDocument(update)
	if err != nil {
		return UpdateResult{}, err
	}
	if err := validateUpdate(u); err != nil {
		return UpdateResult{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var result UpdateResult
	next := make([]map[string]any, len(c.docs))
	copy(next, c.docs)
	for i, doc := range c.docs {
		ok, err := matchDocument(doc, f)
		if err != nil {
			return UpdateResult{}, err
		}
		if !ok {
			continue
		}
		updated := deepCopy(doc).(map[string]any)
		if err := applyUpdate(updated, u, false); err != nil {
			return UpdateResult{}, err
		}
		result.Matched++
		if !reflect.DeepEqual(doc, updated) {
			result.Modified++
		}
		next[i] = updated
	}
	c.docs = next
	return result, nil
}

func (c *MemoryCollection) DeleteOne(ctx context.Context, filter Document) (DeleteResult, error) {
	return c.deleteMatching(ctx, filter, 1)
}

func (c *MemoryCollection) DeleteMany(ctx context.Context, filter Document) (DeleteResult, error) {
	return c.deleteMatching(ctx, filter, -1)
}

func (c *MemoryCollection) deleteMatching(ctx context.Context, filter Document, limit int) (DeleteResult, error) {
	if err := checkContext(ctx); err != nil {
		return DeleteResult{}, err
	}
	f, err := normalizeDocument(filter)
	if err != nil {
		return DeleteResult{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.docs[:0:0]
	var deleted int64
	for _, doc := range c.docs {
		if limit < 0 || deleted < int64(limit) {
			ok, err := matchDocument(doc, f)
			if err != nil {
				return DeleteResult{}, err
			}
			if ok {
				deleted++
				continue
			}
		}
		kept = append(kept, doc)
	}
	c.docs = kept
	return DeleteResult{Deleted: deleted}, nil
}

// checkUnique enforces _id and declared unique indexes. skip is the index of
// the document being replaced (or -1 for an insert).
func (c *MemoryCollection) checkUnique(doc map[string]any, skip int) error {
	indexes := append([][]string{{"_id"}}, c.uniques...)
	for _, fields := range indexes {
		key, ok := uniqueKey(doc, fields)
		if !ok {
			continue
		}
		for i, other := range c.docs {
			if i == skip {
				continue
			}
			if otherKey, ok := uniqueKey(other, fields); ok && valuesEqual(key, otherKey) {
				return ErrConflict
			}
		}
	}
	return nil
}

func uniqueKey(doc map[string]any, fields []string) ([]any, bool) {
	key := make([]any, len(fields))
	present := false
	for i, field := range fields {
		value, ok := lookupPath(doc, field)
		if ok {
			present = true
		}
		key[i] = value
	}
	return key, present
}

// ---- BSON normalization ----

// normalizeDocument converts any BSON-marshalable value into the canonical
// in-memory form: map[string]any for documents, []any for arrays and the
// driver's native Go types for scalars.
func normalizeDocument(value any) (map[string]any, error) {
	if value == nil {
		return map[string]any{}, nil
	}
	if doc, ok := value.(Document); ok {
		value = ToBSON(doc)
	}
	raw, err := bson.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("memdoc: marshal: %w", err)
	}
	return rawToMap(bson.Raw(raw))
}

func rawToMap(raw bson.Raw) (map[string]any, error) {
	elements, err := raw.Elements()
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(elements))
	for _, element := range elements {
		value, err := rawValueToGo(element.Value())
		if err != nil {
			return nil, err
		}
		out[element.Key()] = value
	}
	return out, nil
}

func rawValueToGo(value bson.RawValue) (any, error) {
	switch value.Type {
	case bsontype.EmbeddedDocument:
		return rawToMap(value.Document())
	case bsontype.Array:
		values, err := value.Array().Values()
		if err != nil {
			return nil, err
		}
		out := make([]any, len(values))
		for i, item := range values {
			converted, err := rawValueToGo(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case bsontype.Double:
		return value.Double(), nil
	case bsontype.String:
		return value.StringValue(), nil
	case bsontype.Boolean:
		return value.Boolean(), nil
	case bsontype.Int32:
		return value.Int32(), nil
	case bsontype.Int64:
		return value.Int64(), nil
	case bsontype.Null, bsontype.Undefined:
		return nil, nil
	case bsontype.ObjectID:
		return value.ObjectID(), nil
	case bsontype.DateTime:
		return primitive.DateTime(value.DateTime()), nil
	case bsontype.Binary:
		subtype, data := value.Binary()
		return primitive.Binary{Subtype: subtype, Data: append([]byte(nil), data...)}, nil
	default:
		var out any
		if err := value.Unmarshal(&out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func decodeInto(doc map[string]any, dst any) error {
	raw, err := bson.Marshal(doc)
	if err != nil {
		return err
	}
	return bson.Unmarshal(raw, dst)
}

func decodeSliceInto(docs []map[string]any, dst any) error {
	target := reflect.ValueOf(dst)
	if target.Kind() != reflect.Pointer || target.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("memdoc: FindMany destination must be a pointer to a slice, got %T", dst)
	}
	slice := reflect.MakeSlice(target.Elem().Type(), 0, len(docs))
	for _, doc := range docs {
		item := reflect.New(target.Elem().Type().Elem())
		if err := decodeInto(doc, item.Interface()); err != nil {
			return err
		}
		slice = reflect.Append(slice, item.Elem())
	}
	target.Elem().Set(slice)
	return nil
}

func deepCopy(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = deepCopy(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = deepCopy(item)
		}
		return out
	case primitive.Binary:
		return primitive.Binary{Subtype: v.Subtype, Data: append([]byte(nil), v.Data...)}
	default:
		return v
	}
}

// ---- path helpers ----

func lookupPath(doc map[string]any, path string) (any, bool) {
	var current any = doc
	for _, part := range strings.Split(path, ".") {
		switch node := current.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, true
}

// candidateValues resolves a dotted path with Mongo's implicit array
// traversal: "bots.appId" visits every element of the bots array.
func candidateValues(current any, parts []string) []any {
	if len(parts) == 0 {
		return []any{current}
	}
	switch node := current.(type) {
	case map[string]any:
		next, ok := node[parts[0]]
		if !ok {
			return nil
		}
		return candidateValues(next, parts[1:])
	case []any:
		if index, err := strconv.Atoi(parts[0]); err == nil {
			if index >= 0 && index < len(node) {
				return candidateValues(node[index], parts[1:])
			}
			return nil
		}
		var out []any
		for _, item := range node {
			if _, ok := item.(map[string]any); ok {
				out = append(out, candidateValues(item, parts)...)
			}
		}
		return out
	default:
		return nil
	}
}

func setPath(doc map[string]any, path string, value any) error {
	parts := strings.Split(path, ".")
	var current any = doc
	for i, part := range parts {
		last := i == len(parts)-1
		switch node := current.(type) {
		case map[string]any:
			if last {
				node[part] = value
				return nil
			}
			next, ok := node[part]
			if !ok || next == nil {
				next = map[string]any{}
				node[part] = next
			}
			current = next
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 {
				return fmt.Errorf("memdoc: cannot create field %q in array", part)
			}
			if index >= len(node) {
				return fmt.Errorf("%w: array index growth in %q", errMemoryUnsupported, path)
			}
			if last {
				node[index] = value
				return nil
			}
			if node[index] == nil {
				node[index] = map[string]any{}
			}
			current = node[index]
		default:
			return fmt.Errorf("memdoc: cannot traverse %q in %q", part, path)
		}
	}
	return nil
}

func unsetPath(doc map[string]any, path string) {
	parts := strings.Split(path, ".")
	var current any = doc
	for i, part := range parts {
		last := i == len(parts)-1
		switch node := current.(type) {
		case map[string]any:
			if last {
				delete(node, part)
				return
			}
			current = node[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) {
				return
			}
			if last {
				node[index] = nil
				return
			}
			current = node[index]
		default:
			return
		}
	}
}

// ---- filter matching ----

func matchDocument(doc map[string]any, filter map[string]any) (bool, error) {
	for key, condition := range filter {
		switch key {
		case "$and", "$or", "$nor":
			clauses, ok := condition.([]any)
			if !ok {
				return false, fmt.Errorf("memdoc: %s requires an array", key)
			}
			matchedAny := false
			matchedAll := true
			for _, clause := range clauses {
				sub, ok := clause.(map[string]any)
				if !ok {
					return false, fmt.Errorf("memdoc: %s clause must be a document", key)
				}
				ok, err := matchDocument(doc, sub)
				if err != nil {
					return false, err
				}
				matchedAny = matchedAny || ok
				matchedAll = matchedAll && ok
			}
			if (key == "$and" && !matchedAll) || (key == "$or" && !matchedAny) || (key == "$nor" && matchedAny) {
				return false, nil
			}
			continue
		}
		if strings.HasPrefix(key, "$") {
			return false, fmt.Errorf("%w: top-level %s", errMemoryUnsupported, key)
		}
		ok, err := matchField(doc, key, condition)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func isOperatorDocument(value any) (map[string]any, bool) {
	doc, ok := value.(map[string]any)
	if !ok || len(doc) == 0 {
		return nil, false
	}
	for key := range doc {
		if !strings.HasPrefix(key, "$") {
			return nil, false
		}
	}
	return doc, true
}

func matchField(doc map[string]any, path string, condition any) (bool, error) {
	values := candidateValues(doc, strings.Split(path, "."))
	operators, ok := isOperatorDocument(condition)
	if !ok {
		return matchesEquality(values, condition), nil
	}
	for op, operand := range operators {
		ok, err := matchOperator(values, op, operand)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// expandArrays flattens one level of array values so scalar conditions also
// match array elements, as Mongo does.
func expandArrays(values []any) []any {
	var out []any
	for _, value := range values {
		out = append(out, value)
		if array, ok := value.([]any); ok {
			out = append(out, array...)
		}
	}
	return out
}

func matchesEquality(values []any, target any) bool {
	if target == nil && len(values) == 0 {
		return true
	}
	for _, value := range expandArrays(values) {
		if valuesEqual(value, target) {
			return true
		}
	}
	return false
}

func matchOperator(values []any, op string, operand any) (bool, error) {
	switch op {
	case "$eq":
		return matchesEquality(values, operand), nil
	case "$ne":
		return !matchesEquality(values, operand), nil
	case "$gt", "$gte", "$lt", "$lte":
		for _, value := range expandArrays(values) {
			cmp, comparable := compareSameType(value, operand)
			if !comparable {
				continue
			}
			if (op == "$gt" && cmp > 0) || (op == "$gte" && cmp >= 0) || (op == "$lt" && cmp < 0) || (op == "$lte" && cmp <= 0) {
				return true, nil
			}
		}
		return false, nil
	case "$in", "$nin":
		list, ok := operand.([]any)
		if !ok {
			return false, fmt.Errorf("memdoc: %s requires an array", op)
		}
		found := false
		for _, item := range list {
			if matchesEquality(values, item) {
				found = true
				break
			}
		}
		if op == "$in" {
			return found, nil
		}
		return !found, nil
	case "$exists":
		want := truthy(operand)
		return (len(values) > 0) == want, nil
	case "$elemMatch":
		condition, ok := operand.(map[string]any)
		if !ok {
			return false, errors.New("memdoc: $elemMatch requires a document")
		}
		for _, value := range values {
			array, ok := value.([]any)
			if !ok {
				continue
			}
			for _, item := range array {
				if ok, err := matchElement(item, condition); err != nil {
					return false, err
				} else if ok {
					return true, nil
				}
			}
		}
		return false, nil
	case "$size":
		size, ok := numericValue(operand)
		if !ok {
			return false, errors.New("memdoc: $size requires a number")
		}
		for _, value := range values {
			if array, ok := value.([]any); ok && float64(len(array)) == size {
				return true, nil
			}
		}
		return false, nil
	case "$not":
		condition, ok := operand.(map[string]any)
		if !ok {
			return false, errors.New("memdoc: $not requires an operator document")
		}
		for nestedOp, nestedOperand := range condition {
			ok, err := matchOperator(values, nestedOp, nestedOperand)
			if err != nil {
				return false, err
			}
			if ok {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("%w: query operator %s", errMemoryUnsupported, op)
	}
}

// matchElement evaluates a $elemMatch / $pull condition against one element.
func matchElement(item any, condition map[string]any) (bool, error) {
	if operators, ok := isOperatorDocument(condition); ok {
		for op, operand := range operators {
			ok, err := matchOperator([]any{item}, op, operand)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	}
	doc, ok := item.(map[string]any)
	if !ok {
		return false, nil
	}
	return matchDocument(doc, condition)
}

func truthy(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case nil:
		return false
	default:
		if n, ok := numericValue(v); ok {
			return n != 0
		}
		return true
	}
}

func numericValue(value any) (float64, bool) {
	switch v := value.(type) {
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	case int:
		return float64(v), true
	default:
		return 0, false
	}
}

func valuesEqual(a, b any) bool {
	if an, ok := numericValue(a); ok {
		bn, ok := numericValue(b)
		return ok && an == bn
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for key, value := range av {
			other, ok := bv[key]
			if !ok || !valuesEqual(value, other) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !valuesEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}

func compareSameType(a, b any) (int, bool) {
	if an, ok := numericValue(a); ok {
		bn, ok := numericValue(b)
		if !ok {
			return 0, false
		}
		return compareFloat(an, bn), true
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		if !ok {
			return 0, false
		}
		return strings.Compare(av, bv), true
	case bool:
		bv, ok := b.(bool)
		if !ok {
			return 0, false
		}
		return compareBool(av, bv), true
	case primitive.DateTime:
		bv, ok := b.(primitive.DateTime)
		if !ok {
			return 0, false
		}
		return compareFloat(float64(av), float64(bv)), true
	default:
		return 0, false
	}
}

func compareFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareBool(a, b bool) int {
	if a == b {
		return 0
	}
	if !a {
		return -1
	}
	return 1
}

// compareForSort follows Mongo's cross-type sort order for the types used by
// the repositories: missing/null < numbers < strings < documents < arrays <
// booleans < dates.
func compareForSort(a, b any) int {
	ra, rb := sortRank(a), sortRank(b)
	if ra != rb {
		return compareFloat(float64(ra), float64(rb))
	}
	if cmp, ok := compareSameType(a, b); ok {
		return cmp
	}
	return 0
}

func sortRank(value any) int {
	if _, ok := numericValue(value); ok {
		return 1
	}
	switch value.(type) {
	case nil:
		return 0
	case string:
		return 2
	case map[string]any:
		return 3
	case []any:
		return 4
	case primitive.Binary:
		return 5
	case primitive.ObjectID:
		return 6
	case bool:
		return 7
	case primitive.DateTime:
		return 8
	default:
		return 9
	}
}

// ---- updates ----

func seedFromFilter(filter map[string]any) map[string]any {
	doc := map[string]any{}
	for key, value := range filter {
		if strings.HasPrefix(key, "$") {
			continue
		}
		if operators, ok := isOperatorDocument(value); ok {
			if eq, ok := operators["$eq"]; ok {
				_ = setPath(doc, key, deepCopy(eq))
			}
			continue
		}
		_ = setPath(doc, key, deepCopy(value))
	}
	return doc
}

// validateUpdate performs the checks the server runs on the update document
// itself. Real Mongo rejects a malformed update even when the filter matches
// nothing, so callers validate before matching rather than per document.
func validateUpdate(update map[string]any) error {
	if len(update) == 0 {
		return errors.New("memdoc: empty update")
	}
	for op := range update {
		if !strings.HasPrefix(op, "$") {
			return fmt.Errorf("%w: replacement-style update", errMemoryUnsupported)
		}
	}
	return checkConflictingPaths(update)
}

func applyUpdate(doc map[string]any, update map[string]any, inserting bool) error {
	if err := validateUpdate(update); err != nil {
		return err
	}
	for op, rawFields := range update {
		fields, ok := rawFields.(map[string]any)
		if !ok {
			return fmt.Errorf("memdoc: %s requires a document", op)
		}
		for path, operand := range fields {
			if err := applyFieldUpdate(doc, op, path, operand, inserting); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkConflictingPaths rejects updates where one path is a prefix of
// another, which MongoDB rejects with "would create a conflict".
func checkConflictingPaths(update map[string]any) error {
	var paths []string
	for _, rawFields := range update {
		if fields, ok := rawFields.(map[string]any); ok {
			for path := range fields {
				paths = append(paths, path)
			}
		}
	}
	for i, a := range paths {
		for j, b := range paths {
			if i != j && (a == b || strings.HasPrefix(b, a+".")) {
				return fmt.Errorf("memdoc: update paths %q and %q would create a conflict", a, b)
			}
		}
	}
	return nil
}

func applyFieldUpdate(doc map[string]any, op, path string, operand any, inserting bool) error {
	current, exists := lookupPath(doc, path)
	switch op {
	case "$set":
		return setPath(doc, path, deepCopy(operand))
	case "$setOnInsert":
		if inserting {
			return setPath(doc, path, deepCopy(operand))
		}
		return nil
	case "$unset":
		unsetPath(doc, path)
		return nil
	case "$inc":
		delta, ok := numericValue(operand)
		if !ok {
			return fmt.Errorf("memdoc: $inc %q requires a number", path)
		}
		if !exists || current == nil {
			return setPath(doc, path, operand)
		}
		return setPath(doc, path, addNumbers(current, operand, delta))
	case "$max", "$min":
		if !exists || current == nil {
			return setPath(doc, path, deepCopy(operand))
		}
		cmp, comparable := compareSameType(operand, current)
		if !comparable {
			cmp = compareForSort(operand, current)
		}
		if (op == "$max" && cmp > 0) || (op == "$min" && cmp < 0) {
			return setPath(doc, path, deepCopy(operand))
		}
		return nil
	case "$push", "$addToSet":
		var array []any
		if exists && current != nil {
			existing, ok := current.([]any)
			if !ok {
				return fmt.Errorf("memdoc: %s target %q is not an array", op, path)
			}
			array = existing
		}
		items := []any{operand}
		if modifiers, ok := operand.(map[string]any); ok {
			if each, ok := modifiers["$each"]; ok {
				list, ok := each.([]any)
				if !ok {
					return fmt.Errorf("memdoc: %s $each requires an array", op)
				}
				if len(modifiers) > 1 {
					return fmt.Errorf("%w: %s modifiers other than $each", errMemoryUnsupported, op)
				}
				items = list
			}
		}
		for _, item := range items {
			if op == "$addToSet" {
				duplicate := false
				for _, existing := range array {
					if valuesEqual(existing, item) {
						duplicate = true
						break
					}
				}
				if duplicate {
					continue
				}
			}
			array = append(array, deepCopy(item))
		}
		if array == nil {
			array = []any{}
		}
		return setPath(doc, path, array)
	case "$pull":
		if !exists || current == nil {
			return nil
		}
		array, ok := current.([]any)
		if !ok {
			return fmt.Errorf("memdoc: $pull target %q is not an array", path)
		}
		kept := make([]any, 0, len(array))
		for _, item := range array {
			remove := false
			if condition, ok := operand.(map[string]any); ok {
				matched, err := matchElement(item, condition)
				if err != nil {
					return err
				}
				remove = matched
			} else {
				remove = valuesEqual(item, operand)
			}
			if !remove {
				kept = append(kept, item)
			}
		}
		return setPath(doc, path, kept)
	default:
		return fmt.Errorf("%w: update operator %s", errMemoryUnsupported, op)
	}
}

// addNumbers follows BSON numeric promotion: any double yields a double,
// otherwise int64 wins over int32 and int32 overflow widens to int64.
func addNumbers(current, operand any, delta float64) any {
	base, _ := numericValue(current)
	_, currentDouble := current.(float64)
	_, operandDouble := operand.(float64)
	if currentDouble || operandDouble {
		return base + delta
	}
	sum := int64(base) + int64(delta)
	_, currentInt64 := current.(int64)
	_, operandInt64 := operand.(int64)
	if currentInt64 || operandInt64 || sum > math.MaxInt32 || sum < math.MinInt32 {
		return sum
	}
	return int32(sum)
}

var _ DocumentDatabase = (*MemoryDatabase)(nil)
var _ DocumentCollection = (*MemoryCollection)(nil)
