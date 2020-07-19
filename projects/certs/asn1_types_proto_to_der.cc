#include "asn1_types_proto_to_der.h"

namespace asn1_types {

void ASN1TypesProtoToDER::EncodeIdentifier(const Identifier& id,
                                     const uint32_t tag,
                                     std::vector<uint8_t>& encoder_) {
  // The class comprises the the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  uint8_t id_class = static_cast<uint8_t>(id.id_class()) << 6;
  // The encoding comprises the 6th bit of the identifier (X.690 (2015), 8.1.2).
  uint8_t encoding = static_cast<uint8_t>(id.encoding()) << 5;
  encoder_.push_back((id_class | encoding | tag));
}

std::vector<uint8_t> ASN1TypesProtoToDER::ParseBitString(
    const ASN1BitString& bit_string) {
  std::vector<uint8_t> encoder_;
  EncodeIdentifier(bit_string.id(), 0x03, encoder_);
  return encoder_;
}

}  // namespace asn1_types