#include "asn1_primitive_types_to_der.h"

namespace asn1_primitive_types {

uint8_t ASN1PrimitiveTypesToDER::GetNumBytes(const size_t num) {
  for (uint8_t num_bits = sizeof(num) * 8; num_bits > __CHAR_BIT__;
       num_bits -= __CHAR_BIT__) {
    if (num >> num_bits) {
      return ceil((double)num_bits / __CHAR_BIT__);
    }
  }
  // Special-case: zero requires one, not zero bytes.
  return 1;
}

void ASN1PrimitiveTypesToDER::EncodeDefiniteLength(const size_t len,
                                                   std::vector<uint8_t>& der) {
  der.push_back(len);
  // X.690 (2015), 8.1.3.3: The long-form is used when the length is
  // larger than 127.
  // Note: |len_num_bytes| is not checked here, because it will return
  // 1 for values [128..255], but those require the long-form length.
  if (len > 127) {
    // See X.690 (2015) 8.1.3.5.
    // Long-form length is encoded as a byte with the high-bit set to indicate
    // the long-form, while the remaining bits indicate how many bytes are used
    // to encode the length.
    der.insert(der.begin() + 1, (0x80 | GetNumBytes(len)));
  }
}

void ASN1PrimitiveTypesToDER::EncodeIdentifier(const Identifier& id,
                                               const uint32_t tag,
                                               std::vector<uint8_t>& der) {
  // The class comprises the the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  uint8_t id_class = static_cast<uint8_t>(id.id_class()) << 6;
  // The encoding, which is the 6th bit, is zero for primitive (X.690
  // (2015), 8.1.2).
  der.push_back((id_class | tag));
}

std::vector<uint8_t> ASN1PrimitiveTypesToDER::EncodeBitString(
    const BitString& bit_string) {
  std::vector<uint8_t> der;
  EncodeIdentifier(bit_string.id(), 0x03, der);
  EncodeDefiniteLength(bit_string.val().size() + 1, der);
  // There are no unused bits.
  // This also acts as EOC if val is empty.
  der.push_back(0x00);
  der.insert(der.end(), bit_string.val().begin(), bit_string.val().end());
  return der;
}

std::vector<uint8_t> ASN1PrimitiveTypesToDER::EncodeInteger(
    const Integer& asn1_int) {
  std::vector<uint8_t> der;
  EncodeIdentifier(asn1_int.id(), 0x02, der);
  EncodeDefiniteLength(asn1_int.val().size(), der);
  der.insert(der.end(), asn1_int.val().begin(), asn1_int.val().end());
  return der;
}

std::vector<uint8_t> ASN1PrimitiveTypesToDER::EncodeUTCTime(
    const UTCTime& utc_time) {
  std::vector<uint8_t> der;
  EncodeIdentifier(utc_time.id(), 0x17, der);
  const google::protobuf::Descriptor* desc = utc_time.GetDescriptor();
  const google::protobuf::Reflection* ref = utc_time.GetReflection();
  for (int i = 1; i <= 12; i++) {
    der.push_back(0x30 + ref->GetEnumValue(utc_time, desc->field(i)));
  }
  if (utc_time.zulu()) {
    der.push_back(0x5a);
    der.insert(der.begin() + 1, 13);
  } else {
    der.insert(der.begin() + 1, 12);
  }
  return der;
}

std::vector<uint8_t> ASN1PrimitiveTypesToDER::EncodeGeneralizedTime(
    const GeneralizedTime& generalized_time) {
  std::vector<uint8_t> der;
  EncodeIdentifier(generalized_time.id(), 0x18, der);
  const google::protobuf::Descriptor* desc = generalized_time.GetDescriptor();
  const google::protobuf::Reflection* ref = generalized_time.GetReflection();
  for (int i = 1; i <= 14; i++) {
    der.push_back(0x30 + ref->GetEnumValue(generalized_time, desc->field(i)));
  }
  if (generalized_time.zulu()) {
    der.push_back(0x5a);
    der.insert(der.begin() + 1, 15);
  } else {
    der.insert(der.begin() + 1, 14);
  }
  return der;
}

}  // namespace asn1_primitive_types