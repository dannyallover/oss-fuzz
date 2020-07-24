#ifndef ASN1_PRIMITIVE_TYPES_TO_DER_H_
#define ASN1_PRIMITIVE_TYPES_TO_DER_H_

#include <vector>
#include "asn1_primitive_types.pb.h"

namespace asn1_primitive_types {

class ASN1PrimitiveTypesToDER {
 public:
  std::vector<uint8_t> EncodeBitString(const BitString& bit_string);
  std::vector<uint8_t> EncodeInteger(const Integer& asn1_int);
  std::vector<uint8_t> EncodeUTCTime(const UTCTime& utc_time);

 private:
  uint8_t GetNumBytes(const size_t num);
  void EncodeDefiniteLength(const size_t len, std::vector<uint8_t>& encoder_);
  void EncodeIdentifier(const Identifier& id,
                        const uint32_t tag,
                        std::vector<uint8_t>& encoder_);
};
}  // namespace asn1_types

#endif