// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v3.21.5
// source: udpa/annotations/security.proto

package annotations

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type FieldSecurityAnnotation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ConfigureForUntrustedDownstream bool `protobuf:"varint,1,opt,name=configure_for_untrusted_downstream,json=configureForUntrustedDownstream,proto3" json:"configure_for_untrusted_downstream,omitempty"`
	ConfigureForUntrustedUpstream   bool `protobuf:"varint,2,opt,name=configure_for_untrusted_upstream,json=configureForUntrustedUpstream,proto3" json:"configure_for_untrusted_upstream,omitempty"`
}

func (x *FieldSecurityAnnotation) Reset() {
	*x = FieldSecurityAnnotation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_udpa_annotations_security_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FieldSecurityAnnotation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FieldSecurityAnnotation) ProtoMessage() {}

func (x *FieldSecurityAnnotation) ProtoReflect() protoreflect.Message {
	mi := &file_udpa_annotations_security_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FieldSecurityAnnotation.ProtoReflect.Descriptor instead.
func (*FieldSecurityAnnotation) Descriptor() ([]byte, []int) {
	return file_udpa_annotations_security_proto_rawDescGZIP(), []int{0}
}

func (x *FieldSecurityAnnotation) GetConfigureForUntrustedDownstream() bool {
	if x != nil {
		return x.ConfigureForUntrustedDownstream
	}
	return false
}

func (x *FieldSecurityAnnotation) GetConfigureForUntrustedUpstream() bool {
	if x != nil {
		return x.ConfigureForUntrustedUpstream
	}
	return false
}

var file_udpa_annotations_security_proto_extTypes = []protoimpl.ExtensionInfo{
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*FieldSecurityAnnotation)(nil),
		Field:         11122993,
		Name:          "udpa.annotations.security",
		Tag:           "bytes,11122993,opt,name=security",
		Filename:      "udpa/annotations/security.proto",
	},
}

// Extension fields to descriptorpb.FieldOptions.
var (
	// optional udpa.annotations.FieldSecurityAnnotation security = 11122993;
	E_Security = &file_udpa_annotations_security_proto_extTypes[0]
)

var File_udpa_annotations_security_proto protoreflect.FileDescriptor

var file_udpa_annotations_security_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x10, 0x75, 0x64, 0x70, 0x61, 0x2e, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xaf, 0x01, 0x0a, 0x17, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x53, 0x65,
	0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x41, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x4b, 0x0a, 0x22, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x5f, 0x66, 0x6f,
	0x72, 0x5f, 0x75, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x64, 0x6f, 0x77, 0x6e,
	0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x1f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x46, 0x6f, 0x72, 0x55, 0x6e, 0x74, 0x72, 0x75, 0x73,
	0x74, 0x65, 0x64, 0x44, 0x6f, 0x77, 0x6e, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x47, 0x0a,
	0x20, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x5f, 0x66, 0x6f, 0x72, 0x5f, 0x75,
	0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61,
	0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x1d, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75,
	0x72, 0x65, 0x46, 0x6f, 0x72, 0x55, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x55, 0x70,
	0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x3a, 0x67, 0x0a, 0x08, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69,
	0x74, 0x79, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x18, 0xb1, 0xf2, 0xa6, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x75, 0x64, 0x70,
	0x61, 0x2e, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x46, 0x69,
	0x65, 0x6c, 0x64, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x41, 0x6e, 0x6e, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x42,
	0x31, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x08, 0x01, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6e, 0x63, 0x66, 0x2f, 0x78, 0x64, 0x73, 0x2f, 0x67,
	0x6f, 0x2f, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_udpa_annotations_security_proto_rawDescOnce sync.Once
	file_udpa_annotations_security_proto_rawDescData = file_udpa_annotations_security_proto_rawDesc
)

func file_udpa_annotations_security_proto_rawDescGZIP() []byte {
	file_udpa_annotations_security_proto_rawDescOnce.Do(func() {
		file_udpa_annotations_security_proto_rawDescData = protoimpl.X.CompressGZIP(file_udpa_annotations_security_proto_rawDescData)
	})
	return file_udpa_annotations_security_proto_rawDescData
}

var file_udpa_annotations_security_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_udpa_annotations_security_proto_goTypes = []interface{}{
	(*FieldSecurityAnnotation)(nil),   // 0: udpa.annotations.FieldSecurityAnnotation
	(*descriptorpb.FieldOptions)(nil), // 1: google.protobuf.FieldOptions
}
var file_udpa_annotations_security_proto_depIdxs = []int32{
	1, // 0: udpa.annotations.security:extendee -> google.protobuf.FieldOptions
	0, // 1: udpa.annotations.security:type_name -> udpa.annotations.FieldSecurityAnnotation
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	1, // [1:2] is the sub-list for extension type_name
	0, // [0:1] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_udpa_annotations_security_proto_init() }
func file_udpa_annotations_security_proto_init() {
	if File_udpa_annotations_security_proto != nil {
		return
	}
	file_udpa_annotations_status_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_udpa_annotations_security_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FieldSecurityAnnotation); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_udpa_annotations_security_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 1,
			NumServices:   0,
		},
		GoTypes:           file_udpa_annotations_security_proto_goTypes,
		DependencyIndexes: file_udpa_annotations_security_proto_depIdxs,
		MessageInfos:      file_udpa_annotations_security_proto_msgTypes,
		ExtensionInfos:    file_udpa_annotations_security_proto_extTypes,
	}.Build()
	File_udpa_annotations_security_proto = out.File
	file_udpa_annotations_security_proto_rawDesc = nil
	file_udpa_annotations_security_proto_goTypes = nil
	file_udpa_annotations_security_proto_depIdxs = nil
}
