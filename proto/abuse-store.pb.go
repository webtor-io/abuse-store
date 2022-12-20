// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: abuse-store.proto

package abuse_store

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type PushRequest_Cause int32

const (
	PushRequest_ILLEGAL_CONTENT PushRequest_Cause = 0
	PushRequest_MALWARE         PushRequest_Cause = 1
	PushRequest_APP_ERROR       PushRequest_Cause = 2
	PushRequest_QUESTION        PushRequest_Cause = 3
)

// Enum value maps for PushRequest_Cause.
var (
	PushRequest_Cause_name = map[int32]string{
		0: "ILLEGAL_CONTENT",
		1: "MALWARE",
		2: "APP_ERROR",
		3: "QUESTION",
	}
	PushRequest_Cause_value = map[string]int32{
		"ILLEGAL_CONTENT": 0,
		"MALWARE":         1,
		"APP_ERROR":       2,
		"QUESTION":        3,
	}
)

func (x PushRequest_Cause) Enum() *PushRequest_Cause {
	p := new(PushRequest_Cause)
	*p = x
	return p
}

func (x PushRequest_Cause) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PushRequest_Cause) Descriptor() protoreflect.EnumDescriptor {
	return file_abuse_store_proto_enumTypes[0].Descriptor()
}

func (PushRequest_Cause) Type() protoreflect.EnumType {
	return &file_abuse_store_proto_enumTypes[0]
}

func (x PushRequest_Cause) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PushRequest_Cause.Descriptor instead.
func (PushRequest_Cause) EnumDescriptor() ([]byte, []int) {
	return file_abuse_store_proto_rawDescGZIP(), []int{1, 0}
}

type PushRequest_Source int32

const (
	PushRequest_MAIL PushRequest_Source = 0
	PushRequest_FORM PushRequest_Source = 1
)

// Enum value maps for PushRequest_Source.
var (
	PushRequest_Source_name = map[int32]string{
		0: "MAIL",
		1: "FORM",
	}
	PushRequest_Source_value = map[string]int32{
		"MAIL": 0,
		"FORM": 1,
	}
)

func (x PushRequest_Source) Enum() *PushRequest_Source {
	p := new(PushRequest_Source)
	*p = x
	return p
}

func (x PushRequest_Source) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PushRequest_Source) Descriptor() protoreflect.EnumDescriptor {
	return file_abuse_store_proto_enumTypes[1].Descriptor()
}

func (PushRequest_Source) Type() protoreflect.EnumType {
	return &file_abuse_store_proto_enumTypes[1]
}

func (x PushRequest_Source) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PushRequest_Source.Descriptor instead.
func (PushRequest_Source) EnumDescriptor() ([]byte, []int) {
	return file_abuse_store_proto_rawDescGZIP(), []int{1, 1}
}

// The push response message containing
type PushReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PushReply) Reset() {
	*x = PushReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_abuse_store_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushReply) ProtoMessage() {}

func (x *PushReply) ProtoReflect() protoreflect.Message {
	mi := &file_abuse_store_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushReply.ProtoReflect.Descriptor instead.
func (*PushReply) Descriptor() ([]byte, []int) {
	return file_abuse_store_proto_rawDescGZIP(), []int{0}
}

// The push request message
type PushRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NoticeId    string             `protobuf:"bytes,1,opt,name=notice_id,json=noticeId,proto3" json:"notice_id,omitempty"`
	Infohash    string             `protobuf:"bytes,2,opt,name=infohash,proto3" json:"infohash,omitempty"`
	Filename    string             `protobuf:"bytes,3,opt,name=filename,proto3" json:"filename,omitempty"`
	Work        string             `protobuf:"bytes,4,opt,name=work,proto3" json:"work,omitempty"`
	StartedAt   int64              `protobuf:"varint,5,opt,name=started_at,json=startedAt,proto3" json:"started_at,omitempty"`
	Email       string             `protobuf:"bytes,6,opt,name=email,proto3" json:"email,omitempty"`
	Description string             `protobuf:"bytes,7,opt,name=description,proto3" json:"description,omitempty"`
	Subject     string             `protobuf:"bytes,8,opt,name=subject,proto3" json:"subject,omitempty"`
	Cause       PushRequest_Cause  `protobuf:"varint,9,opt,name=cause,proto3,enum=PushRequest_Cause" json:"cause,omitempty"`
	Source      PushRequest_Source `protobuf:"varint,10,opt,name=source,proto3,enum=PushRequest_Source" json:"source,omitempty"`
}

func (x *PushRequest) Reset() {
	*x = PushRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_abuse_store_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushRequest) ProtoMessage() {}

func (x *PushRequest) ProtoReflect() protoreflect.Message {
	mi := &file_abuse_store_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushRequest.ProtoReflect.Descriptor instead.
func (*PushRequest) Descriptor() ([]byte, []int) {
	return file_abuse_store_proto_rawDescGZIP(), []int{1}
}

func (x *PushRequest) GetNoticeId() string {
	if x != nil {
		return x.NoticeId
	}
	return ""
}

func (x *PushRequest) GetInfohash() string {
	if x != nil {
		return x.Infohash
	}
	return ""
}

func (x *PushRequest) GetFilename() string {
	if x != nil {
		return x.Filename
	}
	return ""
}

func (x *PushRequest) GetWork() string {
	if x != nil {
		return x.Work
	}
	return ""
}

func (x *PushRequest) GetStartedAt() int64 {
	if x != nil {
		return x.StartedAt
	}
	return 0
}

func (x *PushRequest) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *PushRequest) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *PushRequest) GetSubject() string {
	if x != nil {
		return x.Subject
	}
	return ""
}

func (x *PushRequest) GetCause() PushRequest_Cause {
	if x != nil {
		return x.Cause
	}
	return PushRequest_ILLEGAL_CONTENT
}

func (x *PushRequest) GetSource() PushRequest_Source {
	if x != nil {
		return x.Source
	}
	return PushRequest_MAIL
}

// The check request message containing the infoHash
type CheckRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Infohash string `protobuf:"bytes,1,opt,name=infohash,proto3" json:"infohash,omitempty"`
}

func (x *CheckRequest) Reset() {
	*x = CheckRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_abuse_store_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CheckRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CheckRequest) ProtoMessage() {}

func (x *CheckRequest) ProtoReflect() protoreflect.Message {
	mi := &file_abuse_store_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CheckRequest.ProtoReflect.Descriptor instead.
func (*CheckRequest) Descriptor() ([]byte, []int) {
	return file_abuse_store_proto_rawDescGZIP(), []int{2}
}

func (x *CheckRequest) GetInfohash() string {
	if x != nil {
		return x.Infohash
	}
	return ""
}

// The check response message containing existance flag
type CheckReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Exists bool `protobuf:"varint,1,opt,name=exists,proto3" json:"exists,omitempty"`
}

func (x *CheckReply) Reset() {
	*x = CheckReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_abuse_store_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CheckReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CheckReply) ProtoMessage() {}

func (x *CheckReply) ProtoReflect() protoreflect.Message {
	mi := &file_abuse_store_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CheckReply.ProtoReflect.Descriptor instead.
func (*CheckReply) Descriptor() ([]byte, []int) {
	return file_abuse_store_proto_rawDescGZIP(), []int{3}
}

func (x *CheckReply) GetExists() bool {
	if x != nil {
		return x.Exists
	}
	return false
}

var File_abuse_store_proto protoreflect.FileDescriptor

var file_abuse_store_proto_rawDesc = []byte{
	0x0a, 0x11, 0x61, 0x62, 0x75, 0x73, 0x65, 0x2d, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x0b, 0x0a, 0x09, 0x50, 0x75, 0x73, 0x68, 0x52, 0x65, 0x70, 0x6c, 0x79,
	0x22, 0xa4, 0x03, 0x0a, 0x0b, 0x50, 0x75, 0x73, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x1b, 0x0a, 0x09, 0x6e, 0x6f, 0x74, 0x69, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x6e, 0x6f, 0x74, 0x69, 0x63, 0x65, 0x49, 0x64, 0x12, 0x1a, 0x0a,
	0x08, 0x69, 0x6e, 0x66, 0x6f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x69, 0x6e, 0x66, 0x6f, 0x68, 0x61, 0x73, 0x68, 0x12, 0x1a, 0x0a, 0x08, 0x66, 0x69, 0x6c,
	0x65, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x69, 0x6c,
	0x65, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x77, 0x6f, 0x72, 0x6b, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x77, 0x6f, 0x72, 0x6b, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x61,
	0x72, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x73,
	0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69,
	0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x20,
	0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x18, 0x0a, 0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x28, 0x0a, 0x05, 0x63, 0x61,
	0x75, 0x73, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x12, 0x2e, 0x50, 0x75, 0x73, 0x68,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x43, 0x61, 0x75, 0x73, 0x65, 0x52, 0x05, 0x63,
	0x61, 0x75, 0x73, 0x65, 0x12, 0x2b, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x50, 0x75, 0x73, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x2e, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x22, 0x46, 0x0a, 0x05, 0x43, 0x61, 0x75, 0x73, 0x65, 0x12, 0x13, 0x0a, 0x0f, 0x49, 0x4c,
	0x4c, 0x45, 0x47, 0x41, 0x4c, 0x5f, 0x43, 0x4f, 0x4e, 0x54, 0x45, 0x4e, 0x54, 0x10, 0x00, 0x12,
	0x0b, 0x0a, 0x07, 0x4d, 0x41, 0x4c, 0x57, 0x41, 0x52, 0x45, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09,
	0x41, 0x50, 0x50, 0x5f, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x02, 0x12, 0x0c, 0x0a, 0x08, 0x51,
	0x55, 0x45, 0x53, 0x54, 0x49, 0x4f, 0x4e, 0x10, 0x03, 0x22, 0x1c, 0x0a, 0x06, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x12, 0x08, 0x0a, 0x04, 0x4d, 0x41, 0x49, 0x4c, 0x10, 0x00, 0x12, 0x08, 0x0a,
	0x04, 0x46, 0x4f, 0x52, 0x4d, 0x10, 0x01, 0x22, 0x2a, 0x0a, 0x0c, 0x43, 0x68, 0x65, 0x63, 0x6b,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x69, 0x6e, 0x66, 0x6f, 0x68,
	0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x69, 0x6e, 0x66, 0x6f, 0x68,
	0x61, 0x73, 0x68, 0x22, 0x24, 0x0a, 0x0a, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x52, 0x65, 0x70, 0x6c,
	0x79, 0x12, 0x16, 0x0a, 0x06, 0x65, 0x78, 0x69, 0x73, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x06, 0x65, 0x78, 0x69, 0x73, 0x74, 0x73, 0x32, 0x57, 0x0a, 0x0a, 0x41, 0x62, 0x75,
	0x73, 0x65, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x12, 0x22, 0x0a, 0x04, 0x50, 0x75, 0x73, 0x68, 0x12,
	0x0c, 0x2e, 0x50, 0x75, 0x73, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x0a, 0x2e,
	0x50, 0x75, 0x73, 0x68, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x12, 0x25, 0x0a, 0x05, 0x43,
	0x68, 0x65, 0x63, 0x6b, 0x12, 0x0d, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x0b, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x52, 0x65, 0x70, 0x6c, 0x79,
	0x22, 0x00, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_abuse_store_proto_rawDescOnce sync.Once
	file_abuse_store_proto_rawDescData = file_abuse_store_proto_rawDesc
)

func file_abuse_store_proto_rawDescGZIP() []byte {
	file_abuse_store_proto_rawDescOnce.Do(func() {
		file_abuse_store_proto_rawDescData = protoimpl.X.CompressGZIP(file_abuse_store_proto_rawDescData)
	})
	return file_abuse_store_proto_rawDescData
}

var file_abuse_store_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_abuse_store_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_abuse_store_proto_goTypes = []interface{}{
	(PushRequest_Cause)(0),  // 0: PushRequest.Cause
	(PushRequest_Source)(0), // 1: PushRequest.Source
	(*PushReply)(nil),       // 2: PushReply
	(*PushRequest)(nil),     // 3: PushRequest
	(*CheckRequest)(nil),    // 4: CheckRequest
	(*CheckReply)(nil),      // 5: CheckReply
}
var file_abuse_store_proto_depIdxs = []int32{
	0, // 0: PushRequest.cause:type_name -> PushRequest.Cause
	1, // 1: PushRequest.source:type_name -> PushRequest.Source
	3, // 2: AbuseStore.Push:input_type -> PushRequest
	4, // 3: AbuseStore.Check:input_type -> CheckRequest
	2, // 4: AbuseStore.Push:output_type -> PushReply
	5, // 5: AbuseStore.Check:output_type -> CheckReply
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_abuse_store_proto_init() }
func file_abuse_store_proto_init() {
	if File_abuse_store_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_abuse_store_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushReply); i {
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
		file_abuse_store_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushRequest); i {
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
		file_abuse_store_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CheckRequest); i {
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
		file_abuse_store_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CheckReply); i {
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
			RawDescriptor: file_abuse_store_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_abuse_store_proto_goTypes,
		DependencyIndexes: file_abuse_store_proto_depIdxs,
		EnumInfos:         file_abuse_store_proto_enumTypes,
		MessageInfos:      file_abuse_store_proto_msgTypes,
	}.Build()
	File_abuse_store_proto = out.File
	file_abuse_store_proto_rawDesc = nil
	file_abuse_store_proto_goTypes = nil
	file_abuse_store_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// AbuseStoreClient is the client API for AbuseStore service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AbuseStoreClient interface {
	// Pushes abuse to the store
	Push(ctx context.Context, in *PushRequest, opts ...grpc.CallOption) (*PushReply, error)
	// Check abuse in the store for existence
	Check(ctx context.Context, in *CheckRequest, opts ...grpc.CallOption) (*CheckReply, error)
}

type abuseStoreClient struct {
	cc grpc.ClientConnInterface
}

func NewAbuseStoreClient(cc grpc.ClientConnInterface) AbuseStoreClient {
	return &abuseStoreClient{cc}
}

func (c *abuseStoreClient) Push(ctx context.Context, in *PushRequest, opts ...grpc.CallOption) (*PushReply, error) {
	out := new(PushReply)
	err := c.cc.Invoke(ctx, "/AbuseStore/Push", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *abuseStoreClient) Check(ctx context.Context, in *CheckRequest, opts ...grpc.CallOption) (*CheckReply, error) {
	out := new(CheckReply)
	err := c.cc.Invoke(ctx, "/AbuseStore/Check", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AbuseStoreServer is the server API for AbuseStore service.
type AbuseStoreServer interface {
	// Pushes abuse to the store
	Push(context.Context, *PushRequest) (*PushReply, error)
	// Check abuse in the store for existence
	Check(context.Context, *CheckRequest) (*CheckReply, error)
}

// UnimplementedAbuseStoreServer can be embedded to have forward compatible implementations.
type UnimplementedAbuseStoreServer struct {
}

func (*UnimplementedAbuseStoreServer) Push(context.Context, *PushRequest) (*PushReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Push not implemented")
}
func (*UnimplementedAbuseStoreServer) Check(context.Context, *CheckRequest) (*CheckReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Check not implemented")
}

func RegisterAbuseStoreServer(s *grpc.Server, srv AbuseStoreServer) {
	s.RegisterService(&_AbuseStore_serviceDesc, srv)
}

func _AbuseStore_Push_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PushRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AbuseStoreServer).Push(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/AbuseStore/Push",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AbuseStoreServer).Push(ctx, req.(*PushRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AbuseStore_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AbuseStoreServer).Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/AbuseStore/Check",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AbuseStoreServer).Check(ctx, req.(*CheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AbuseStore_serviceDesc = grpc.ServiceDesc{
	ServiceName: "AbuseStore",
	HandlerType: (*AbuseStoreServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Push",
			Handler:    _AbuseStore_Push_Handler,
		},
		{
			MethodName: "Check",
			Handler:    _AbuseStore_Check_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "abuse-store.proto",
}
