#include "asn1_types_to_der.h"

namespace asn1_types {

uint8_t ASN1TypesToDER::GetNumBytes(const size_t num) {
  for (uint8_t num_bits = sizeof(num) * 8; num_bits > __CHAR_BIT__;
       num_bits -= __CHAR_BIT__) {
    if (num >> num_bits) {
      return ceil((double)num_bits / __CHAR_BIT__);
    }
  }
  // Special-case: zero requires one, not zero bytes.
  return 1;
}

void ASN1TypesToDER::EncodeDefiniteLength(const size_t len,
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

void ASN1TypesToDER::EncodeIdentifier(const Class& id_class,
                                      const bool constructed,
                                      const uint32_t tag_num,
                                      std::vector<uint8_t>& der) {
  // The class comprises the the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  uint8_t class_bits = static_cast<uint8_t>(id_class) << 6;
  // The encoding, which is the 6th bit, is zero for primitive (X.690
  // (2015), 8.1.2).
  der.push_back((class_bits | tag_num));
}

std::vector<uint8_t> ASN1TypesToDER::EncodeBitString(
    const BitString& bit_string) {
  std::vector<uint8_t> der;
  EncodeIdentifier(bit_string.id_class(), false, 0x03, der);
  EncodeDefiniteLength(bit_string.val().size() + 1, der);
  // There are no unused bits.
  // This also acts as EOC if val is empty.
  der.push_back(0x00);
  der.insert(der.end(), bit_string.val().begin(), bit_string.val().end());
  return der;
}

std::vector<uint8_t> ASN1TypesToDER::EncodeInteger(const Integer& integer) {
  std::vector<uint8_t> der;
  EncodeIdentifier(integer.id_class(), false, 0x02, der);
  EncodeDefiniteLength(integer.val().size(), der);
  der.insert(der.end(), integer.val().begin(), integer.val().end());
  return der;
}

std::vector<uint8_t> ASN1TypesToDER::EncodeUTCTime(const UTCTime& utc_time) {
  std::vector<uint8_t> der;
  EncodeIdentifier(utc_time.id_class(), false, 0x17, der);
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

std::vector<uint8_t> ASN1TypesToDER::EncodeGeneralizedTime(
    const GeneralizedTime& generalized_time) {
  std::vector<uint8_t> der;
  EncodeIdentifier(generalized_time.id_class(), false, 0x18, der);
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

std::vector<uint8_t> ASN1TypesToDER::EncodeAlgorithmIdentifier(
    const AlgorithmIdentifier& algorithm_identifier) {
  std::vector<uint8_t> der;
  EncodeIdentifier(algorithm_identifier.id_class(), true, 0x10, der);
  size_t len = algorithm_identifier.object_identifier().size() +
               algorithm_identifier.parameters().size();
  der.push_back(len);
  der.insert(der.end(), algorithm_identifier.object_identifier().begin(),
             algorithm_identifier.object_identifier().end());
  der.insert(der.end(), algorithm_identifier.parameters().begin(),
             algorithm_identifier.parameters().end());
  return der;
}

}  // namespace asn1_types