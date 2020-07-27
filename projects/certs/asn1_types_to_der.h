#ifndef ASN1_TYPES_TO_DER_H_
#define ASN1_TYPES_TO_DER_H_

#include <vector>

#include "asn1_types.pb.h"

namespace asn1_types {

class ASN1TypesToDER {
 public:
 // comment here
  std::vector<uint8_t> EncodeBitString(const BitString& bit_string);

  // comment here
  std::vector<uint8_t> EncodeInteger(const Integer& integer);

  // comment here
  std::vector<uint8_t> EncodeUTCTime(const UTCTime& utc_time);

  // comment here
  std::vector<uint8_t> EncodeGeneralizedTime(
      const GeneralizedTime& generalized_time);

// comment here
  std::vector<uint8_t> EncodeAlgorithmIdentifier(
      const AlgorithmIdentifier& algorithm_identifier);

 private:
 //comment here
  uint8_t GetNumBytes(const size_t num);

  //comment here
  void EncodeDefiniteLength(const size_t len, std::vector<uint8_t>& encoder_);

  // comment here
  void EncodeIdentifier(const Class& id_class,
                        const bool constructed,
                        const uint32_t tag_num,
                        std::vector<uint8_t>& der);
};
}  // namespace asn1_types

#endif