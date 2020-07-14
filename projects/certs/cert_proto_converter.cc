#include "cert_proto_converter.h"

namespace cert_proto {

std::string CertProtoConverter::EncodeCert(const X509Certificate &cert) {
  der_ << "hello";
  return der_.str();
}

} // namespace cert_proto