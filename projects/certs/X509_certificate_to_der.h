#ifndef CERT_PROTO_CONVERTER_H_
#define CERT_PROTO_CONVERTER_H_

#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <vector>
#include "X509_certificate.pb.h"
#include "asn1_pdu_to_der.h"
#include "asn1_primitive_types_to_der.h"

namespace X509_certificate {

class CertToDER {
 public:
  std::vector<uint8_t> X509CertificateToDER(
      const X509Certificate& X509_certificate);

 private:
  size_t depth_;
  std::vector<uint8_t> encoder_;
  asn1_pdu::ASN1PDUToDER pdu_to_der;
  asn1_primitive_types::ASN1PrimitiveTypesToDER primitive_types_to_der;
  void EncodeX509Certificate(const X509Certificate& cert);
  void EncodeSignatureValue(const SignatureValue& signature);
  void EncodeTBSCertificate(const TBSCertificate& tbs_certificate);
  void EncodeVersion(const Version& version);
  void EncodeCertificateSerialNumber(
      const CertificateSerialNumber& cert_serial_num);
  void EncodeValidity(const Validity& validity);
  void EncodeExtensions(const Extensions& extensions);
};

}  // namespace X509_certificate

#endif