#ifndef CERT_PROTO_CONVERTER_H_
#define CERT_PROTO_CONVERTER_H_

#include <typeinfo>
#include <vector>

#include "X509_certificate.pb.h"
#include "asn1_pdu_to_der.h"
#include "asn1_universal_types_to_der.h"

namespace x509_certificate {

class CertToDER {
 public:
  // Encodes |X509_certificate| to DER, returning the encoded bytes of the PDU
  // in |der_|.
  std::vector<uint8_t> X509CertificateToDER(
      const X509Certificate& X509_certificate);

 private:
  // Contains encoded X509 Certificate.
  std::vector<uint8_t> der_;

  // Used to encode PDU's for fields that contain them.
  asn1_pdu::ASN1PDUToDER pdu_to_der;

  // Used to encode the ASN1 types that appear in X509 Certificates.
  asn1_universal_types::ASN1UniversalTypesToDER u_types_to_der;

  template <typename T>
  void Encode(const T& t);

  // Encode(FIELD) DER encodes the field found in X509 Certificates
  // and writes the results to |der_|.
  void Encode(const asn1_pdu::PDU& pdu);
  void Encode(const TBSCertificateValue& tbs_certificate);
  void Encode(const SubjectPublicKeyInfoValue& subject_public_key_info);
  void Encode(const ValidityValue& validity);
  void Encode(const TimeChoice& val);
  void Encode(const asn1_universal_types::GeneralizedTime& generalized_time);
  void Encode(const asn1_universal_types::UTCTime& utc_time);
  void Encode(const VersionNumber& version);
  void Encode(const asn1_universal_types::Integer& integer);
  void Encode(const AlgorithmIdentifier& algorithm_identifier);
  void Encode(const asn1_universal_types::BitString& bit_string);
};

}  // namespace x509_certificate

#endif