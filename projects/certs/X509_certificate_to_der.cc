#include "X509_certificate_to_der.h"

namespace X509_certificate {

void CertToDER::EncodeBitString(const asn1_types::BitString& bit_string) {
  std::vector<uint8_t> der = types_to_der.EncodeBitString(bit_string);
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeInteger(const asn1_types::Integer& integer) {
  std::vector<uint8_t> der = types_to_der.EncodeInteger(integer);
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeAlgorithmIdentifier(
    const asn1_types::AlgorithmIdentifier& algorithm_identifier) {
  std::vector<uint8_t> der =
      types_to_der.EncodeAlgorithmIdentifier(algorithm_identifier);
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodePDU(const asn1_pdu::PDU& pdu) {
  std::vector<uint8_t> der = pdu_to_der.PDUToDER(pdu);
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

template <typename T>
bool CertToDER::UseInvalidField(const T field) {
  return field.has_pdu();
}

void CertToDER::EncodeSequenceIdentifier(const asn1_types::Class& sequence_class) {
  encoder_.push_back((sequence_class << 7) | (1 << 6) | 0x10);
}

void CertToDER::EncodeExtensions(const Extensions& extensions) {
  EncodePDU(extensions.pdu());
}

void CertToDER::EncodeIssuerUniqueId(const IssuerUniqueId& issuer_unique_id) {
  if (UseInvalidField(issuer_unique_id.unique_identifier())) {
    return EncodePDU(issuer_unique_id.unique_identifier().pdu());
  }
  EncodeBitString(issuer_unique_id.unique_identifier().bit_string());
}

void CertToDER::EncodeSubjectUniqueId(const SubjectUniqueId& subject_unique_id) {
  if (UseInvalidField(subject_unique_id.unique_identifier())) {
    return EncodePDU(subject_unique_id.unique_identifier().pdu());
  }
  EncodeBitString(subject_unique_id.unique_identifier().bit_string());
}

void CertToDER::EncodeSubjectPublicKey(
    const SubjectPublicKey& subject_public_key) {
  if (UseInvalidField(subject_public_key)) {
    return EncodePDU(subject_public_key.pdu());
  }
  EncodeBitString(subject_public_key.bit_string());
}

void CertToDER::EncodeSubjectPublicKeyInfo(
    const SubjectPublicKeyInfo& subject_public_key_info) {
  EncodeSequenceIdentifier(subject_public_key_info.sequence_class());
  size_t len_pos = encoder_.size();
  EncodeAlgorithmIdentifier(subject_public_key_info.algorithm_identifier());
  EncodeSubjectPublicKey(subject_public_key_info.subject_public_key());
  encoder_.insert(encoder_.begin() + len_pos, encoder_.size() - len_pos);
}

void CertToDER::EncodeName(const Name& name) {
  EncodePDU(name.pdu());
}

void CertToDER::EncodeSubject(const Subject& subject) {
  EncodeName(subject.name());
}

void CertToDER::EncodeTime(const Time& time) {
  if (UseInvalidField(time)) {
    return EncodePDU(time.pdu());
  }

  std::vector<uint8_t> der;
  if (time.has_utc_time()) {
    der = types_to_der.EncodeUTCTime(time.utc_time());
  } else {
    der = types_to_der.EncodeGeneralizedTime(time.generalized_time());
  }
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeValidity(const Validity& validity) {
  EncodeSequenceIdentifier(validity.sequence_class());
  size_t len_pos = encoder_.size();
  EncodeTime(validity.not_before().time());
  EncodeTime(validity.not_after().time());
  encoder_.insert(encoder_.begin() + len_pos, encoder_.size() - len_pos);
}

void CertToDER::EncodeIssuer(const Issuer& issuer) {
  EncodeName(issuer.name());
}

void CertToDER::EncodeSignature(const Signature& signature) {
  EncodeAlgorithmIdentifier(signature.algorithm_identifier());
}

void CertToDER::EncodeSerialNumber(
    const SerialNumber& serial_num) {
  if (UseInvalidField(serial_num)) {
    return EncodePDU(serial_num.pdu());
  }
  EncodeInteger(serial_num.integer());
}

void CertToDER::EncodeVersion(const Version& version) {
  if (UseInvalidField(version)) {
    return EncodePDU(version.pdu());
  }
  // comment on v2 v3 stuff
  std::vector<uint8_t> der = {0x02, 0x01,
                              static_cast<uint8_t>(version.version_number())};
  encoder_.insert(encoder_.end(), der.begin(), der.end());
}

void CertToDER::EncodeTBSCertificate(const TBSCertificate& tbs_certificate) {
  EncodeSequenceIdentifier(tbs_certificate.sequence_class());
  size_t len_pos = encoder_.size();
  EncodeVersion(tbs_certificate.version());
  EncodeSerialNumber(tbs_certificate.serial_number());
  EncodeSignature(tbs_certificate.signature());
  EncodeIssuer(tbs_certificate.issuer());
  EncodeValidity(tbs_certificate.validity());
  EncodeSubject(tbs_certificate.subject());
  EncodeSubjectPublicKeyInfo(tbs_certificate.subject_public_key_info());
  if (tbs_certificate.has_issuer_unique_id()) {
    EncodeIssuerUniqueId(tbs_certificate.issuer_unique_id());
  }
  if(tbs_certificate.has_subject_unique_id()) {
    EncodeSubjectUniqueId(tbs_certificate.subject_unique_id());
  }
  if(tbs_certificate.has_extensions()) {
    EncodeExtensions(tbs_certificate.extensions());
  }
  encoder_.insert(encoder_.begin() + len_pos, encoder_.size() - len_pos);
}

void CertToDER::EncodeSignatureAlgorithm(
    const SignatureAlgorithm& signature_algorithm) {
  if (UseInvalidField(signature_algorithm)) {
    return EncodePDU(signature_algorithm.pdu());
  }
  EncodeAlgorithmIdentifier(signature_algorithm.algorithm_identifier());
}

void CertToDER::EncodeSignatureValue(const SignatureValue& signature_value) {
  if (UseInvalidField(signature_value)) {
    return EncodePDU(signature_value.pdu());
  }
  EncodeBitString(signature_value.bit_string());
}

void CertToDER::EncodeX509Certificate(const X509Certificate& X509_certificate) {
  EncodeSequenceIdentifier(X509_certificate.sequence_class());
  size_t len_pos = encoder_.size();
  EncodeTBSCertificate(X509_certificate.tbs_certificate());
  EncodeSignatureValue(X509_certificate.signature_value());
  encoder_.insert(encoder_.begin() + len_pos, encoder_.size() - len_pos);
}

std::vector<uint8_t> CertToDER::X509CertificateToDER(
    const X509Certificate& X509_certificate) {
  encoder_.clear();
  EncodeX509Certificate(X509_certificate);
  return encoder_;
}

}  // namespace X509_certificate