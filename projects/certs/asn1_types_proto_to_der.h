#ifndef ASN1_TYPES_PROTO_CONVERTER_H_
#define ASN1_TYPES_PROTO_CONVERTER_H_

#include <vector>
#include "asn1_types.pb.h"

namespace asn1_types {
    
class ASN1TypesProtoToDER {
 public:
  std::vector<uint8_t> EncodeBitString(const ASN1BitString& bit_string);

 private:
  void EncodeIdentifier(const Identifier& id,
                  const uint32_t tag,
                  std::vector<uint8_t>& encoder_);
};
}  // namespace asn1_types

#endif