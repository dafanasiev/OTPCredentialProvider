// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: OTPCheckService.proto

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "OTPCheckService.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace api {
class CheckRequestDefaultTypeInternal {
public:
 ::google::protobuf::internal::ExplicitlyConstructed<CheckRequest>
     _instance;
} _CheckRequest_default_instance_;
class CheckResponseDefaultTypeInternal {
public:
 ::google::protobuf::internal::ExplicitlyConstructed<CheckResponse>
     _instance;
} _CheckResponse_default_instance_;

namespace protobuf_OTPCheckService_2eproto {


namespace {

::google::protobuf::Metadata file_level_metadata[2];
const ::google::protobuf::EnumDescriptor* file_level_enum_descriptors[1];

}  // namespace

PROTOBUF_CONSTEXPR_VAR ::google::protobuf::internal::ParseTableField
    const TableStruct::entries[] GOOGLE_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  {0, 0, 0, ::google::protobuf::internal::kInvalidMask, 0, 0},
};

PROTOBUF_CONSTEXPR_VAR ::google::protobuf::internal::AuxillaryParseTableField
    const TableStruct::aux[] GOOGLE_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  ::google::protobuf::internal::AuxillaryParseTableField(),
};
PROTOBUF_CONSTEXPR_VAR ::google::protobuf::internal::ParseTable const
    TableStruct::schema[] GOOGLE_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  { NULL, NULL, 0, -1, -1, -1, -1, NULL, false },
  { NULL, NULL, 0, -1, -1, -1, -1, NULL, false },
};

const ::google::protobuf::uint32 TableStruct::offsets[] GOOGLE_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CheckRequest, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CheckRequest, type_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CheckRequest, login_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CheckRequest, code_),
  ~0u,  // no _has_bits_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CheckResponse, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
};
static const ::google::protobuf::internal::MigrationSchema schemas[] GOOGLE_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(CheckRequest)},
  { 8, -1, sizeof(CheckResponse)},
};

static ::google::protobuf::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::google::protobuf::Message*>(&_CheckRequest_default_instance_),
  reinterpret_cast<const ::google::protobuf::Message*>(&_CheckResponse_default_instance_),
};

namespace {

void protobuf_AssignDescriptors() {
  AddDescriptors();
  ::google::protobuf::MessageFactory* factory = NULL;
  AssignDescriptors(
      "OTPCheckService.proto", schemas, file_default_instances, TableStruct::offsets, factory,
      file_level_metadata, file_level_enum_descriptors, NULL);
}

void protobuf_AssignDescriptorsOnce() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &protobuf_AssignDescriptors);
}

void protobuf_RegisterTypes(const ::std::string&) GOOGLE_ATTRIBUTE_COLD;
void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::internal::RegisterAllTypes(file_level_metadata, 2);
}

}  // namespace
void TableStruct::InitDefaultsImpl() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::internal::InitProtobufDefaults();
  _CheckRequest_default_instance_._instance.DefaultConstruct();
  ::google::protobuf::internal::OnShutdownDestroyMessage(
      &_CheckRequest_default_instance_);_CheckResponse_default_instance_._instance.DefaultConstruct();
  ::google::protobuf::internal::OnShutdownDestroyMessage(
      &_CheckResponse_default_instance_);}

void InitDefaults() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &TableStruct::InitDefaultsImpl);
}
namespace {
void AddDescriptorsImpl() {
  InitDefaults();
  static const char descriptor[] GOOGLE_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
      "\n\025OTPCheckService.proto\022\003api\"i\n\014CheckReq"
      "uest\022\'\n\004type\030\001 \001(\0162\031.api.CheckRequest.OT"
      "PType\022\r\n\005login\030\002 \001(\t\022\014\n\004code\030\003 \001(\t\"\023\n\007OT"
      "PType\022\010\n\004TOTP\020\000\"\017\n\rCheckResponse2<\n\010OTPC"
      "heck\0220\n\005Check\022\021.api.CheckRequest\032\022.api.C"
      "heckResponse\"\000b\006proto3"
  };
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
      descriptor, 222);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "OTPCheckService.proto", &protobuf_RegisterTypes);
}
} // anonymous namespace

void AddDescriptors() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &AddDescriptorsImpl);
}
// Force AddDescriptors() to be called at dynamic initialization time.
struct StaticDescriptorInitializer {
  StaticDescriptorInitializer() {
    AddDescriptors();
  }
} static_descriptor_initializer;

}  // namespace protobuf_OTPCheckService_2eproto

const ::google::protobuf::EnumDescriptor* CheckRequest_OTPType_descriptor() {
  protobuf_OTPCheckService_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_OTPCheckService_2eproto::file_level_enum_descriptors[0];
}
bool CheckRequest_OTPType_IsValid(int value) {
  switch (value) {
    case 0:
      return true;
    default:
      return false;
  }
}

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const CheckRequest_OTPType CheckRequest::TOTP;
const CheckRequest_OTPType CheckRequest::OTPType_MIN;
const CheckRequest_OTPType CheckRequest::OTPType_MAX;
const int CheckRequest::OTPType_ARRAYSIZE;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

// ===================================================================

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int CheckRequest::kTypeFieldNumber;
const int CheckRequest::kLoginFieldNumber;
const int CheckRequest::kCodeFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

CheckRequest::CheckRequest()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  if (GOOGLE_PREDICT_TRUE(this != internal_default_instance())) {
    protobuf_OTPCheckService_2eproto::InitDefaults();
  }
  SharedCtor();
  // @@protoc_insertion_point(constructor:api.CheckRequest)
}
CheckRequest::CheckRequest(const CheckRequest& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL),
      _cached_size_(0) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  login_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.login().size() > 0) {
    login_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.login_);
  }
  code_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.code().size() > 0) {
    code_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.code_);
  }
  type_ = from.type_;
  // @@protoc_insertion_point(copy_constructor:api.CheckRequest)
}

void CheckRequest::SharedCtor() {
  login_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  code_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  type_ = 0;
  _cached_size_ = 0;
}

CheckRequest::~CheckRequest() {
  // @@protoc_insertion_point(destructor:api.CheckRequest)
  SharedDtor();
}

void CheckRequest::SharedDtor() {
  login_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  code_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

void CheckRequest::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* CheckRequest::descriptor() {
  protobuf_OTPCheckService_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_OTPCheckService_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const CheckRequest& CheckRequest::default_instance() {
  protobuf_OTPCheckService_2eproto::InitDefaults();
  return *internal_default_instance();
}

CheckRequest* CheckRequest::New(::google::protobuf::Arena* arena) const {
  CheckRequest* n = new CheckRequest;
  if (arena != NULL) {
    arena->Own(n);
  }
  return n;
}

void CheckRequest::Clear() {
// @@protoc_insertion_point(message_clear_start:api.CheckRequest)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  login_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  code_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  type_ = 0;
  _internal_metadata_.Clear();
}

bool CheckRequest::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:api.CheckRequest)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // .api.CheckRequest.OTPType type = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(8u /* 8 & 0xFF */)) {
          int value;
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   int, ::google::protobuf::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          set_type(static_cast< ::api::CheckRequest_OTPType >(value));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // string login = 2;
      case 2: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(18u /* 18 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_login()));
          DO_(::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
            this->login().data(), static_cast<int>(this->login().length()),
            ::google::protobuf::internal::WireFormatLite::PARSE,
            "api.CheckRequest.login"));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // string code = 3;
      case 3: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(26u /* 26 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_code()));
          DO_(::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
            this->code().data(), static_cast<int>(this->code().length()),
            ::google::protobuf::internal::WireFormatLite::PARSE,
            "api.CheckRequest.code"));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, _internal_metadata_.mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:api.CheckRequest)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:api.CheckRequest)
  return false;
#undef DO_
}

void CheckRequest::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:api.CheckRequest)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .api.CheckRequest.OTPType type = 1;
  if (this->type() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteEnum(
      1, this->type(), output);
  }

  // string login = 2;
  if (this->login().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->login().data(), static_cast<int>(this->login().length()),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "api.CheckRequest.login");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      2, this->login(), output);
  }

  // string code = 3;
  if (this->code().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->code().data(), static_cast<int>(this->code().length()),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "api.CheckRequest.code");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      3, this->code(), output);
  }

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), output);
  }
  // @@protoc_insertion_point(serialize_end:api.CheckRequest)
}

::google::protobuf::uint8* CheckRequest::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  (void)deterministic; // Unused
  // @@protoc_insertion_point(serialize_to_array_start:api.CheckRequest)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .api.CheckRequest.OTPType type = 1;
  if (this->type() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::WriteEnumToArray(
      1, this->type(), target);
  }

  // string login = 2;
  if (this->login().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->login().data(), static_cast<int>(this->login().length()),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "api.CheckRequest.login");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        2, this->login(), target);
  }

  // string code = 3;
  if (this->code().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
      this->code().data(), static_cast<int>(this->code().length()),
      ::google::protobuf::internal::WireFormatLite::SERIALIZE,
      "api.CheckRequest.code");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        3, this->code(), target);
  }

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:api.CheckRequest)
  return target;
}

size_t CheckRequest::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:api.CheckRequest)
  size_t total_size = 0;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()));
  }
  // string login = 2;
  if (this->login().size() > 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::StringSize(
        this->login());
  }

  // string code = 3;
  if (this->code().size() > 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::StringSize(
        this->code());
  }

  // .api.CheckRequest.OTPType type = 1;
  if (this->type() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::EnumSize(this->type());
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = cached_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void CheckRequest::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:api.CheckRequest)
  GOOGLE_DCHECK_NE(&from, this);
  const CheckRequest* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const CheckRequest>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:api.CheckRequest)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:api.CheckRequest)
    MergeFrom(*source);
  }
}

void CheckRequest::MergeFrom(const CheckRequest& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:api.CheckRequest)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.login().size() > 0) {

    login_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.login_);
  }
  if (from.code().size() > 0) {

    code_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.code_);
  }
  if (from.type() != 0) {
    set_type(from.type());
  }
}

void CheckRequest::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:api.CheckRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void CheckRequest::CopyFrom(const CheckRequest& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:api.CheckRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool CheckRequest::IsInitialized() const {
  return true;
}

void CheckRequest::Swap(CheckRequest* other) {
  if (other == this) return;
  InternalSwap(other);
}
void CheckRequest::InternalSwap(CheckRequest* other) {
  using std::swap;
  login_.Swap(&other->login_);
  code_.Swap(&other->code_);
  swap(type_, other->type_);
  _internal_metadata_.Swap(&other->_internal_metadata_);
  swap(_cached_size_, other->_cached_size_);
}

::google::protobuf::Metadata CheckRequest::GetMetadata() const {
  protobuf_OTPCheckService_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_OTPCheckService_2eproto::file_level_metadata[kIndexInFileMessages];
}

#if PROTOBUF_INLINE_NOT_IN_HEADERS
// CheckRequest

// .api.CheckRequest.OTPType type = 1;
void CheckRequest::clear_type() {
  type_ = 0;
}
::api::CheckRequest_OTPType CheckRequest::type() const {
  // @@protoc_insertion_point(field_get:api.CheckRequest.type)
  return static_cast< ::api::CheckRequest_OTPType >(type_);
}
void CheckRequest::set_type(::api::CheckRequest_OTPType value) {
  
  type_ = value;
  // @@protoc_insertion_point(field_set:api.CheckRequest.type)
}

// string login = 2;
void CheckRequest::clear_login() {
  login_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
const ::std::string& CheckRequest::login() const {
  // @@protoc_insertion_point(field_get:api.CheckRequest.login)
  return login_.GetNoArena();
}
void CheckRequest::set_login(const ::std::string& value) {
  
  login_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:api.CheckRequest.login)
}
#if LANG_CXX11
void CheckRequest::set_login(::std::string&& value) {
  
  login_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:api.CheckRequest.login)
}
#endif
void CheckRequest::set_login(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  login_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:api.CheckRequest.login)
}
void CheckRequest::set_login(const char* value, size_t size) {
  
  login_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:api.CheckRequest.login)
}
::std::string* CheckRequest::mutable_login() {
  
  // @@protoc_insertion_point(field_mutable:api.CheckRequest.login)
  return login_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
::std::string* CheckRequest::release_login() {
  // @@protoc_insertion_point(field_release:api.CheckRequest.login)
  
  return login_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
void CheckRequest::set_allocated_login(::std::string* login) {
  if (login != NULL) {
    
  } else {
    
  }
  login_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), login);
  // @@protoc_insertion_point(field_set_allocated:api.CheckRequest.login)
}

// string code = 3;
void CheckRequest::clear_code() {
  code_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
const ::std::string& CheckRequest::code() const {
  // @@protoc_insertion_point(field_get:api.CheckRequest.code)
  return code_.GetNoArena();
}
void CheckRequest::set_code(const ::std::string& value) {
  
  code_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:api.CheckRequest.code)
}
#if LANG_CXX11
void CheckRequest::set_code(::std::string&& value) {
  
  code_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:api.CheckRequest.code)
}
#endif
void CheckRequest::set_code(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  
  code_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:api.CheckRequest.code)
}
void CheckRequest::set_code(const char* value, size_t size) {
  
  code_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:api.CheckRequest.code)
}
::std::string* CheckRequest::mutable_code() {
  
  // @@protoc_insertion_point(field_mutable:api.CheckRequest.code)
  return code_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
::std::string* CheckRequest::release_code() {
  // @@protoc_insertion_point(field_release:api.CheckRequest.code)
  
  return code_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
void CheckRequest::set_allocated_code(::std::string* code) {
  if (code != NULL) {
    
  } else {
    
  }
  code_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), code);
  // @@protoc_insertion_point(field_set_allocated:api.CheckRequest.code)
}

#endif  // PROTOBUF_INLINE_NOT_IN_HEADERS

// ===================================================================

#if !defined(_MSC_VER) || _MSC_VER >= 1900
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

CheckResponse::CheckResponse()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  if (GOOGLE_PREDICT_TRUE(this != internal_default_instance())) {
    protobuf_OTPCheckService_2eproto::InitDefaults();
  }
  SharedCtor();
  // @@protoc_insertion_point(constructor:api.CheckResponse)
}
CheckResponse::CheckResponse(const CheckResponse& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL),
      _cached_size_(0) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:api.CheckResponse)
}

void CheckResponse::SharedCtor() {
  _cached_size_ = 0;
}

CheckResponse::~CheckResponse() {
  // @@protoc_insertion_point(destructor:api.CheckResponse)
  SharedDtor();
}

void CheckResponse::SharedDtor() {
}

void CheckResponse::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* CheckResponse::descriptor() {
  protobuf_OTPCheckService_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_OTPCheckService_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const CheckResponse& CheckResponse::default_instance() {
  protobuf_OTPCheckService_2eproto::InitDefaults();
  return *internal_default_instance();
}

CheckResponse* CheckResponse::New(::google::protobuf::Arena* arena) const {
  CheckResponse* n = new CheckResponse;
  if (arena != NULL) {
    arena->Own(n);
  }
  return n;
}

void CheckResponse::Clear() {
// @@protoc_insertion_point(message_clear_start:api.CheckResponse)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _internal_metadata_.Clear();
}

bool CheckResponse::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:api.CheckResponse)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
  handle_unusual:
    if (tag == 0) {
      goto success;
    }
    DO_(::google::protobuf::internal::WireFormat::SkipField(
          input, tag, _internal_metadata_.mutable_unknown_fields()));
  }
success:
  // @@protoc_insertion_point(parse_success:api.CheckResponse)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:api.CheckResponse)
  return false;
#undef DO_
}

void CheckResponse::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:api.CheckResponse)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), output);
  }
  // @@protoc_insertion_point(serialize_end:api.CheckResponse)
}

::google::protobuf::uint8* CheckResponse::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  (void)deterministic; // Unused
  // @@protoc_insertion_point(serialize_to_array_start:api.CheckResponse)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:api.CheckResponse)
  return target;
}

size_t CheckResponse::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:api.CheckResponse)
  size_t total_size = 0;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()));
  }
  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = cached_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void CheckResponse::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:api.CheckResponse)
  GOOGLE_DCHECK_NE(&from, this);
  const CheckResponse* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const CheckResponse>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:api.CheckResponse)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:api.CheckResponse)
    MergeFrom(*source);
  }
}

void CheckResponse::MergeFrom(const CheckResponse& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:api.CheckResponse)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

}

void CheckResponse::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:api.CheckResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void CheckResponse::CopyFrom(const CheckResponse& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:api.CheckResponse)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool CheckResponse::IsInitialized() const {
  return true;
}

void CheckResponse::Swap(CheckResponse* other) {
  if (other == this) return;
  InternalSwap(other);
}
void CheckResponse::InternalSwap(CheckResponse* other) {
  using std::swap;
  _internal_metadata_.Swap(&other->_internal_metadata_);
  swap(_cached_size_, other->_cached_size_);
}

::google::protobuf::Metadata CheckResponse::GetMetadata() const {
  protobuf_OTPCheckService_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_OTPCheckService_2eproto::file_level_metadata[kIndexInFileMessages];
}

#if PROTOBUF_INLINE_NOT_IN_HEADERS
// CheckResponse

#endif  // PROTOBUF_INLINE_NOT_IN_HEADERS

// @@protoc_insertion_point(namespace_scope)

}  // namespace api

// @@protoc_insertion_point(global_scope)