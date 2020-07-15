#ifndef CERT_PROTO_CONVERTER_H_
#define CERT_PROTO_CONVERTER_H_

#include "cert.pb.h"
#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <vector>

namespace cert_proto {

class CertProtoConverter {
public:
  std::string EncodeCert(const PDU &pdu);

private:
  std::stringstream der_;
  std::vector<uint8_t> encoder_;
  size_t EncodePDU(const PDU &pdu);
  size_t EncodeIdentifier(const Identifier &id);
  uint64_t EncodeHighTagForm(const uint8_t cl, const uint8_t enc,
                             const uint32_t tag);
  size_t EncodeLength(const Length &len, size_t actual_len, size_t len_pos);
  size_t EncodeOverrideLength(const std::string len, const size_t len_pos);
  size_t EncodeIndefiniteLength(const size_t len_pos);
  size_t EncodeCorrectLength(const size_t actual_len, const size_t len_pos);
  size_t EncodeLongForm(size_t assigned_len, size_t len_pos);
  size_t EncodeValue(const Value &val);
  void AppendBytes(size_t num, size_t pos);
  uint8_t GetNumBytes(size_t num);
  void ParseToBits();
};

} // namespace cert_proto

#endif