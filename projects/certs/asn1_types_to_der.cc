#include "asn1_types_to_der.h"

namespace asn1_types {

uint8_t ASN1TypesToDER::GetVariableIntLen(size_t value) {
  for (uint8_t num_bits = sizeof(value) * CHAR_BIT; num_bits > __CHAR_BIT__;
       num_bits -= __CHAR_BIT__) {
    if (value >> num_bits) {
      return ceil((double)num_bits / CHAR_BIT);
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
    der.insert(der.begin() + 1, (0x80 | GetVariableIntLen(len)));
  }
}

void ASN1TypesToDER::EncodeIdentifier(const bool constructed,
                                      const uint32_t tag_num,
                                      std::vector<uint8_t>& der) {
  // The encoding, which is the 6th bit in the identifier, is 1 for constructed
  // (X.690 (2015), 8.1.2).
  uint8_t encoding = constructed ? 1 << 5 : 0;
  der.push_back((encoding | tag_num));
}

std::vector<uint8_t> ASN1TypesToDER::EncodeBitString(
    const BitString& bit_string) {
  std::vector<uint8_t> der;
  // BitString has tag number 3 (X.208, Table 1).
  EncodeIdentifier(bit_string.encoding(), 0x03, der);
  // Add one to the length for the unused bits byte.
  EncodeDefiniteLength(bit_string.val().size() + 1, der);
  // Encode 0 to indicate that there are no unused bits.
  // This also acts as EOC if val is empty.
  der.push_back(0x00);
  der.insert(der.end(), bit_string.val().begin(), bit_string.val().end());
  return der;
}

std::vector<uint8_t> ASN1TypesToDER::EncodeInteger(const Integer& integer) {
  std::vector<uint8_t> der;
  // Integer has tag number 2 (X.208, Table 1) and is always primitive (X.690
  // (2015), 8.3.1).
  EncodeIdentifier(false, 0x02, der);
  EncodeDefiniteLength(integer.val().size(), der);
  der.insert(der.end(), integer.val().begin(), integer.val().end());
  return der;
}

std::vector<uint8_t> ASN1TypesToDER::EncodeUTCTime(const UTCTime& utc_time) {
  std::vector<uint8_t> der;
  // UTCTime has tag number 3 (X.208, Table 1).
  EncodeIdentifier(false, 0x17, der);
  const google::protobuf::Descriptor* desc = utc_time.GetDescriptor();
  const google::protobuf::Reflection* ref = utc_time.GetReflection();
  for (int i = 1; i <= 12; i++) {
    // UTCTime is encoded like a string so add 0x30 to get ascii character.
    der.push_back(0x30 + ref->GetEnumValue(utc_time, desc->field(i)));
  }
  // The encoding shall terminate with "Z" (ITU-T X.680 | ISO/IEC 8824-1).
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
  // GeneralizedTime has tag number 3 (X.208, Table 1).
  EncodeIdentifier(false, 0x18, der);
  const google::protobuf::Descriptor* desc = generalized_time.GetDescriptor();
  const google::protobuf::Reflection* ref = generalized_time.GetReflection();
  for (int i = 1; i <= 14; i++) {
    // GeneralizedTime is encoded like a string so add 0x30 to get ascii
    // character.
    der.push_back(0x30 + ref->GetEnumValue(generalized_time, desc->field(i)));
  }
  // The encoding shall terminate with "Z" (ITU-T X.680 | ISO/IEC 8824-1).
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
  // AlgorithmIdentifier is a sequence (RFC 5280, 4.1.1.2) which is constructed
  // (X.690 (2015), 8.9.1).
  EncodeIdentifier(true, 0x10, der);
  size_t len = algorithm_identifier.object_identifier().size() +
               algorithm_identifier.parameters().size();
  EncodeDefiniteLength(len, der);
  der.insert(der.end(), algorithm_identifier.object_identifier().begin(),
             algorithm_identifier.object_identifier().end());
  der.insert(der.end(), algorithm_identifier.parameters().begin(),
             algorithm_identifier.parameters().end());
  return der;
}

}  // namespace asn1_types