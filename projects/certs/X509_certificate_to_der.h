#ifndef CERT_PROTO_CONVERTER_H_
#define CERT_PROTO_CONVERTER_H_

#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <vector>
#include "X509_certificate.pb.h"
#include "asn1_pdu_to_der.h"
#include "asn1_types_to_der.h"

namespace X509_certificate {

class CertToDER {
 public:
  std::vector<uint8_t> X509CertificateToDER(
      const X509Certificate& X509_certificate);

 private:
  size_t depth_;
  std::vector<uint8_t> encoder_;
  asn1_pdu::ASN1PDUToDER pdu_to_der;
  asn1_types::ASN1TypesToDER types_to_der;
  void EncodeX509Certificate(const X509Certificate& cert);
  void EncodeSignatureValue(const SignatureValue& signature);
  void EncodeSignatureAlgorithm(const SignatureAlgorithm& signature_algorithm);
  void EncodeTBSCertificate(const TBSCertificate& tbs_certificate);
  void EncodeVersion(const Version& version);
  void EncodeSerialNumber(const SerialNumber& serial_num);
  void EncodeSignature(const Signature& signature);
  void EncodeIssuer(const Issuer& issuer);
  void EncodeValidity(const Validity& validity);
  void EncodeTime(const Time& time);
  void EncodeSubject(const Subject& subject);
  void EncodeName(const Name& name);
  void EncodeSubjectPublicKeyInfo(
      const SubjectPublicKeyInfo& subject_public_key_info);
  void EncodeSubjectPublicKey(const SubjectPublicKey& subject_public_key);
  void EncodeIssuerUniqueId(const IssuerUniqueId& issuer_unique_id);
  void EncodeSubjectUniqueId(const SubjectUniqueId& subject_unique_id);
  void EncodeExtensions(const Extensions& extensions);
  void EncodeBitString(const asn1_types::BitString& bit_string);
  void EncodeInteger(const asn1_types::Integer& integer);
  void EncodeAlgorithmIdentifier(
      const asn1_types::AlgorithmIdentifier& algorithm_identifier);
  void EncodePDU(const asn1_pdu::PDU& pdu);
  template <typename T>
  bool UseInvalidField(const T field);
  void EncodeSequenceIdentifier(const asn1_types::Class& sequence_class);
};

}  // namespace X509_certificate

#endif