#ifndef CERT_PROTO_CONVERTER_H_
#define CERT_PROTO_CONVERTER_H_

#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <vector>
#include "cert.pb.h"
#include "asn1_types_proto_to_der.h"
#include "asn1_pdu_proto_to_der.h"

namespace cert_proto {

class CertProtoConverter {
 public:
  std::vector<uint8_t> EncodeCertificate(const X509Certificate& cert);

 private:
  size_t depth_;
  std::vector<uint8_t> encoder_;
  asn1_pdu::ASN1PDUProtoToDER pdu2der;
  void ParseToBits();
};

}  // namespace cert_proto

#endif