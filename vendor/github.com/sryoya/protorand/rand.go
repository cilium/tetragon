package protorand

import (
	"fmt"
	"math/rand"
	"reflect"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Chars is the set of characters used to generate random strings.
var Chars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// ProtoRand is a source of random values for protobuf fields.
type ProtoRand struct {
	rand                  *rand.Rand
	MaxCollectionElements int

	// MaxDepth is the maximum stack depth for recursion, which prevents stack overflows if a message is (directly or
	// transitively) self-referential.
	MaxDepth int
}

// New creates a new ProtoRand.
func New() *ProtoRand {
	return &ProtoRand{
		rand:                  rand.New(rand.NewSource(time.Now().UnixNano())),
		MaxCollectionElements: 10,
		MaxDepth:              5,
	}
}

// Seed sets the seed of the random generator.
func (p *ProtoRand) Seed(seed int64) {
	p.rand = rand.New(rand.NewSource(seed))
}

// Gen generates a new proto.Message having random values in its fields.
// The input is used to specify the type of the generated message.
// The input itself is immutable.
func (p *ProtoRand) Gen(in proto.Message) (proto.Message, error) {
	mds := in.ProtoReflect().Descriptor()
	dm, err := p.NewDynamicProtoRand(mds)
	if err != nil {
		return nil, err
	}

	out := reflect.New(reflect.ValueOf(in).Elem().Type()).Interface().(proto.Message)
	proto.Merge(out, dm)
	return out, nil
}

// NewDynamicProtoRand creates dynamicpb with assigning random values to a proto.
func (p *ProtoRand) NewDynamicProtoRand(mds protoreflect.MessageDescriptor) (*dynamicpb.Message, error) {
	return p.newDynamicProtoRand(mds, p.MaxDepth)
}

func (p *ProtoRand) newDynamicProtoRand(mds protoreflect.MessageDescriptor, allowedDepth int) (*dynamicpb.Message, error) {
	getRandValue := func(fd protoreflect.FieldDescriptor) (protoreflect.Value, error) {
		switch fd.FullName() {
		case "google.protobuf.Timestamp":
			const minTimestamp = -62135596800  // Seconds between 1970-01-01T00:00:00Z and 0001-01-01T00:00:00Z, inclusive
			const maxTimestamp = +253402300799 // Seconds between 1970-01-01T00:00:00Z and 9999-12-31T23:59:59Z, inclusive
			const maxNanos = 1e9               // exclusive
			t := &timestamppb.Timestamp{
				Seconds: p.rand.Int63n(maxTimestamp-minTimestamp+1) + minTimestamp,
				Nanos:   p.rand.Int31n(maxNanos),
			}
			return protoreflect.ValueOf(t), nil
		case "google.protobuf.Duration":
			const absDuration = 315576000000 // 10000yr * 365.25day/yr * 24hr/day * 60min/hr * 60sec/min
			const maxNanos = 1e9             // exclusive
			s := p.rand.Int63n(2*absDuration+1) - absDuration
			n := int32(0)
			switch {
			case s == 0:
				n = p.rand.Int31n(2*maxNanos+1) - maxNanos
			case s > 0:
				n = p.rand.Int31n(maxNanos + 1)
			case s < 0:
				n = p.rand.Int31n(maxNanos+1) - maxNanos
			}
			d := &durationpb.Duration{
				Seconds: s,
				Nanos:   n,
			}
			return protoreflect.ValueOf(d), nil
		}
		switch fd.Kind() {
		case protoreflect.Int32Kind:
			return protoreflect.ValueOfInt32(p.randInt32()), nil
		case protoreflect.Int64Kind:
			return protoreflect.ValueOfInt64(p.randInt64()), nil
		case protoreflect.Sint32Kind:
			return protoreflect.ValueOfInt32(p.randInt32()), nil
		case protoreflect.Sint64Kind:
			return protoreflect.ValueOfInt64(p.randInt64()), nil
		case protoreflect.Uint32Kind:
			return protoreflect.ValueOfUint32(p.randUint32()), nil
		case protoreflect.Uint64Kind:
			return protoreflect.ValueOfUint64(p.randUint64()), nil
		case protoreflect.Fixed32Kind:
			return protoreflect.ValueOfUint32(p.randUint32()), nil
		case protoreflect.Fixed64Kind:
			return protoreflect.ValueOfUint64(p.randUint64()), nil
		case protoreflect.Sfixed32Kind:
			return protoreflect.ValueOfInt32(p.randInt32()), nil
		case protoreflect.Sfixed64Kind:
			return protoreflect.ValueOfInt64(p.randInt64()), nil
		case protoreflect.FloatKind:
			return protoreflect.ValueOfFloat32(p.randFloat32()), nil
		case protoreflect.DoubleKind:
			return protoreflect.ValueOfFloat64(p.randFloat64()), nil
		case protoreflect.StringKind:
			return protoreflect.ValueOfString(p.randString()), nil
		case protoreflect.BoolKind:
			return protoreflect.ValueOfBool(p.randBool()), nil
		case protoreflect.EnumKind:
			return protoreflect.ValueOfEnum(p.chooseEnumValueRandomly(fd.Enum().Values())), nil
		case protoreflect.BytesKind:
			return protoreflect.ValueOfBytes(p.randBytes()), nil
		case protoreflect.MessageKind:
			msg := fd.Message()
			switch msg.FullName() {
			case "google.protobuf.Timestamp":
				const minTimestamp = -62135596800  // Seconds between 1970-01-01T00:00:00Z and 0001-01-01T00:00:00Z, inclusive
				const maxTimestamp = +253402300799 // Seconds between 1970-01-01T00:00:00Z and 9999-12-31T23:59:59Z, inclusive
				const maxNanos = 1e9               // exclusive
				t := &timestamppb.Timestamp{
					Seconds: p.rand.Int63n(maxTimestamp-minTimestamp+1) + minTimestamp,
					Nanos:   p.rand.Int31n(maxNanos),
				}
				return protoreflect.ValueOf(t.ProtoReflect()), nil
			case "google.protobuf.Duration":
				const absDuration = 315576000000 // 10000yr * 365.25day/yr * 24hr/day * 60min/hr * 60sec/min
				const maxNanos = 1e9             // exclusive
				s := p.rand.Int63n(2*absDuration+1) - absDuration
				n := int32(0)
				switch {
				case s == 0:
					n = p.rand.Int31n(2*maxNanos+1) - maxNanos
				case s > 0:
					n = p.rand.Int31n(maxNanos + 1)
				case s < 0:
					n = p.rand.Int31n(maxNanos+1) - maxNanos
				}
				d := &durationpb.Duration{
					Seconds: s,
					Nanos:   n,
				}
				return protoreflect.ValueOf(d.ProtoReflect()), nil
			}
			// process recursively (if we have more stacks to give...)
			if allowedDepth > 0 {
				rm, err := p.newDynamicProtoRand(msg, allowedDepth-1)
				if err != nil {
					return protoreflect.Value{}, err
				}
				return protoreflect.ValueOfMessage(rm), nil
			}
			// recursed too deep; just return nil
			return protoreflect.Value{}, nil
		default:
			return protoreflect.Value{}, fmt.Errorf("unexpected type: %v", fd.Kind())
		}
	}

	// decide which fields in each OneOf will be populated in advance
	populatedOneOfField := map[protoreflect.Name]protoreflect.FieldNumber{}
	oneOfs := mds.Oneofs()
	for i := 0; i < oneOfs.Len(); i++ {
		oneOf := oneOfs.Get(i)
		populatedOneOfField[oneOf.Name()] = p.chooseOneOfFieldRandomly(oneOf).Number()
	}

	dm := dynamicpb.NewMessage(mds)
	fds := mds.Fields()
	for k := 0; k < fds.Len(); k++ {
		fd := fds.Get(k)

		// If a field is in OneOf, check if the field should be populated
		if oneOf := fd.ContainingOneof(); oneOf != nil {
			populatedFieldNum := populatedOneOfField[oneOf.Name()]
			if populatedFieldNum != fd.Number() {
				continue
			}
		}

		if fd.IsList() {
			list := dm.Mutable(fd).List()
			n := p.rand.Intn(p.MaxCollectionElements) + 1
			for i := 0; i < n; i++ {
				value, err := getRandValue(fd)
				if err != nil {
					return nil, err
				}
				if value.Interface() != nil {
					list.Append(value)
				}
			}
			dm.Set(fd, protoreflect.ValueOfList(list))
			continue
		}
		if fd.IsMap() {
			mp := dm.Mutable(fd).Map()
			n := p.rand.Intn(p.MaxCollectionElements) + 1
			for i := 0; i < n; i++ {
				key, err := getRandValue(fd.MapKey())
				if err != nil {
					return nil, err
				}
				value, err := getRandValue(fd.MapValue())
				if err != nil {
					return nil, err
				}
				if key.Interface() != nil && value.Interface() != nil {
					mp.Set(protoreflect.MapKey(key), protoreflect.Value(value))
				}
			}
			dm.Set(fd, protoreflect.ValueOfMap(mp))
			continue
		}

		value, err := getRandValue(fd)
		if err != nil {
			return nil, err
		}
		if value.Interface() != nil {
			dm.Set(fd, value)
		}
	}

	return dm, nil
}

func (p *ProtoRand) randInt32() int32 {
	return p.rand.Int31()
}

func (p *ProtoRand) randInt64() int64 {
	return p.rand.Int63()
}

func (p *ProtoRand) randUint32() uint32 {
	return p.rand.Uint32()
}

func (p *ProtoRand) randUint64() uint64 {
	return p.rand.Uint64()
}

func (p *ProtoRand) randFloat32() float32 {
	return p.rand.Float32()
}

func (p *ProtoRand) randFloat64() float64 {
	return p.rand.Float64()
}

func (p *ProtoRand) randBytes() []byte {
	return []byte(p.randString())
}

func (p *ProtoRand) randString() string {
	b := make([]rune, 10) // TODO: make the length randomly or use a predefined length?
	for i := range b {
		b[i] = Chars[p.rand.Intn(len(Chars))]
	}
	return string(b)
}

func (p *ProtoRand) randBool() bool {
	return p.rand.Int31()%2 == 0
}

func (p *ProtoRand) chooseEnumValueRandomly(values protoreflect.EnumValueDescriptors) protoreflect.EnumNumber {
	ln := values.Len()
	if ln <= 1 {
		return 0
	}

	value := values.Get(p.rand.Intn(ln))
	return value.Number()
}

func (p *ProtoRand) chooseOneOfFieldRandomly(oneOf protoreflect.OneofDescriptor) protoreflect.FieldDescriptor {
	ln := oneOf.Fields().Len()
	if ln == 1 {
		return oneOf.Fields().Get(0)
	}
	index := p.rand.Intn(ln)
	return oneOf.Fields().Get(index)
}
