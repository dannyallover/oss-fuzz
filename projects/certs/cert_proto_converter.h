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
  std::string EncodeCert(const X509Certificate &cert);

private:
  std::stringstream der_;
  std::vector<uint8_t> encoder_;
};

} // namespace cert_proto

#endif