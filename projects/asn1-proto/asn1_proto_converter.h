#ifndef ASN1_PROTO_CONVERTER_H_
#define ASN1_PROTO_CONVERTER_H_

#include "asn1.pb.h"
#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <vector>

namespace asn1_proto {

class ASN1ProtoConverter {
public:
  std::string ProtoToDER(const PDU &pdu);

private:
  size_t depth_;
  std::stringstream der_;
  std::vector<uint8_t> encoder_;
  size_t EncodePDU(const PDU &pdu);
  size_t EncodeIdentifier(const Identifier &id);
  uint64_t EncodeHighTagForm(const uint8_t cl, const uint8_t encoding,
                             const uint32_t tag);
  size_t EncodeLength(const Length &len, size_t actual_len, size_t len_pos);
  size_t EncodeOverrideLength(const std::string len, const size_t len_pos);
  size_t EncodeIndefiniteLength(const size_t len_pos);
  size_t EncodeCorrectLength(const size_t actual_len, const size_t len_pos);
  size_t EncodeLongForm(size_t assigned_len, size_t len_pos);
  size_t EncodeValue(const Value &val);
  void AppendBytes(const size_t num, const size_t pos);
  uint8_t GetNumBytes(const size_t num);
  void ParseToBits();
};

} // namespace asn1_proto

#endif
