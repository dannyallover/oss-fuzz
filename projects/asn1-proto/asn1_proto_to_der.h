#ifndef ASN1_PROTO_TO_DER_H_
#define ASN1_PROTO_TO_DER_H_

#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <vector>
#include <cmath>
#include "asn1.pb.h"

namespace asn1_proto {

class ASN1ProtoToDER {
 public:
  // Encodes |pdu| to DER, returning the encoded bytes of the PDU in
  // |encoder_|.
  std::vector<uint8_t> ProtoToDER(const PDU& pdu);

 private:
  size_t depth_;
  std::vector<uint8_t> encoder_;
  // Enocdes |pdu| to DER, returning the number of bytes needed encode |pdu|.
  size_t EncodePDU(const PDU& pdu);
  // Encodes |id| to DER according to X.690 (2015), 8.1.2.
  // Returns number of bytes needed to encode |id|.
  uint8_t EncodeIdentifier(const Identifier& id);
  // Concatinates |id_class|, |encoding|, and |tag| according to DER
  // high-tag-number form rules (X.690 (2015), 8.1.2.4), returning
  // number of bytes needed to encode the identifier.
  uint8_t EncodeHighTagNumberForm(const uint8_t id_class,
                                   const uint8_t encoding,
                                   const uint32_t tag);
  // Encodes the length in |actual_len| to DER, returning the length
  // in bytes of the encoded length. |len_pos| contains the offset in |encoder_|
  // where the length should be encoded. |len| can be used to affect the
  // encoding, in order to produce invalid lengths. To correctly call this, the
  // tag must already be encoded immediately prior to |len_pos|, and the
  // remainder of |encoder_| represents the encoded value.
  size_t EncodeLength(const Length& len, size_t actual_len, size_t len_pos);
  // Writes |raw_length| to |encoder_| at |len_pos| and returns the number of
  // bytes written to |encoder_|.
  size_t EncodeOverrideLength(const std::string raw_len, const size_t len_pos);
  // Encodes the indefinite-length indicator (X.690 (2015), 8.1.3.6) at
  // |len_pos|, and appends an End-of-Contents (EOC) marker at the end of
  // |encoder_|, returning number of bytes needed to encode indefinite-length
  // indicator and EOC.
  size_t EncodeIndefiniteLength(const size_t len_pos);
  // Encodes the length in |actual_len| using the definite-form length (X.690
  // (2015), 8.1.3-8.1.5 & 10.1) into |encoder_| at |len_pos|, returning number
  // of bytes needed to encode |actual_len|.
  size_t EncodeDefiniteLength(const size_t actual_len, const size_t len_pos);
  // Extracts bytes from |val| and inserts them into |enocder_|, returning
  // number of bytes needed to encode |val|.
  size_t EncodeValue(const Value& val);
  // Converts |num| to a variable-length, big-endian representation and inserts
  // the result into into |encoder_| at |pos|.
  void AppendBytes(const size_t num, const size_t pos);
  // Returns the number of bytes needed to |base| encode |num| into a
  // variable-length unsigned integer with no leading zeros.
  uint8_t GetNumBytes(const size_t num, const size_t base);
  // Prints bits in |encoder_|. Used for testing and validation.
  void PrintEncodedBits();
};

}  // namespace asn1_proto

#endif
