#ifndef ASN1_TYPES_TO_DER_H_
#define ASN1_TYPES_TO_DER_H_

#include <vector>

#include "asn1_types.pb.h"

namespace asn1_types {

class ASN1TypesToDER {
 public:
  std::vector<uint8_t> EncodeBitString(const BitString& bit_string);
  std::vector<uint8_t> EncodeInteger(const Integer& integer);
  std::vector<uint8_t> EncodeUTCTime(const UTCTime& utc_time);
  std::vector<uint8_t> EncodeGeneralizedTime(
      const GeneralizedTime& generalized_time);

 private:
  uint8_t GetVariableIntLen(size_t value);
  void EncodeDefiniteLength(const size_t len, std::vector<uint8_t>& encoder_);
  void EncodeIdentifier(const bool constructed,
                        const uint32_t tag_num,
                        std::vector<uint8_t>& der);
};

}  // namespace asn1_types

#endif