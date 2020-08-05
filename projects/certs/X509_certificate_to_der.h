#ifndef CERT_PROTO_CONVERTER_H_
#define CERT_PROTO_CONVERTER_H_

#include <typeinfo>
#include <vector>

#include "X509_certificate.pb.h"
#include "asn1_pdu_to_der.h"
#include "asn1_universal_types_to_der.h"

namespace x509_certificate {

// Encodes |X509_certificate| to DER, returning the encoded bytes in |der_|.
std::vector<uint8_t> X509CertificateToDER(
    const X509Certificate& X509_certificate);

// Encodes a |pdu| if |t| contains one; otherwise, encodes the value belonging
// to |t|.
template <typename T>
void Encode(const T& t, std::vector<uint8_t>& der) {
  if (t.has_pdu()) {
    Encode(t.pdu(), der);
    return;
  }
  Encode(t.value(), der);
}

// Encodes the |TYPE| found in X509 Certificates and writes the results to
// |der|.
#define DECLARE_ENCODE_FUNCTION(TYPE, TYPE_NAME) \
  template <>                                    \
  void Encode<TYPE>(const TYPE& TYPE_NAME, std::vector<uint8_t>& der)

DECLARE_ENCODE_FUNCTION(TBSCertificateSequence, tbs_certificate);
DECLARE_ENCODE_FUNCTION(VersionNumber, version);
DECLARE_ENCODE_FUNCTION(ValiditySequence, validity);
DECLARE_ENCODE_FUNCTION(TimeChoice, val);
DECLARE_ENCODE_FUNCTION(SubjectPublicKeyInfoSequence, subject_public_key_info);
DECLARE_ENCODE_FUNCTION(AlgorithmIdentifierSequence, algorithm_identifier);
DECLARE_ENCODE_FUNCTION(asn1_pdu::PDU, pdu);

}  // namespace x509_certificate

#endif