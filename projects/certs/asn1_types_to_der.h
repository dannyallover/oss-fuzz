#ifndef ASN1_TYPES_TO_DER_H_
#define ASN1_TYPES_TO_DER_H_

#include <vector>

#include "asn1_pdu_to_der.h"
#include "asn1_types.pb.h"

namespace asn1_types {

class ASN1TypesToDER {
 public:
  std::vector<uint8_t> EncodeBitString(const BitString& bit_string);
  std::vector<uint8_t> EncodeInteger(const Integer& integer);
  std::vector<uint8_t> EncodeUTCTime(const UTCTime& utc_time);
  std::vector<uint8_t> EncodeGeneralizedTime(
      const GeneralizedTime& generalized_time);
  std::vector<uint8_t> EncodeAlgorithmIdentifier(
      const AlgorithmIdentifier& algorithm_identifier);

 private:
  asn1_pdu::ASN1PDUToDER pdu_to_der;
  uint8_t GetNumBytes(const size_t num);
  void EncodeDefiniteLength(const size_t len, std::vector<uint8_t>& encoder_);
  void EncodeIdentifier(const Class& id_class,
                        const bool constructed,
                        const uint32_t tag_num,
                        std::vector<uint8_t>& der);
};
}  // namespace asn1_types

#endif