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
  std::stringstream der_;
  std::vector<uint8_t> encoder_;
  size_t ParsePDU(const PDU &pdu);
  size_t ParseIdentifier(const Identifier &id);
  size_t HighTagForm(const uint8_t cl, const uint8_t enc, const uint32_t tag);
  size_t ParseLength(const Length &len, size_t actual_len, size_t len_pos);
  size_t LongForm(size_t assigned_len, size_t len_pos);
  size_t ParseValue(const Value &val);
  void Append(size_t num, size_t pos);
  uint8_t GetNumBytes(size_t num);
  void ParseToBits();
};

} // namespace asn1_proto

#endif
