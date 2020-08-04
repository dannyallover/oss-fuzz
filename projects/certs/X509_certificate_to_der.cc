#include "X509_certificate_to_der.h"

namespace x509_certificate {

template <>
void Encode<asn1_pdu::PDU>(const asn1_pdu::PDU& pdu,
                           std::vector<uint8_t>& der) {
  // Used to encode PDU's for fields that contain them.
  asn1_pdu::ASN1PDUToDER pdu_to_der;
  std::vector<uint8_t> derpdu = pdu_to_der.PDUToDER(pdu);
  der.insert(der.end(), derpdu.begin(), derpdu.end());
}

template <>
void Encode<AlgorithmIdentifier>(
    const AlgorithmIdentifier& algorithm_identifier,
    std::vector<uint8_t>& der) {
  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der.size();

  der.insert(der.end(), algorithm_identifier.object_identifier().begin(),
             algorithm_identifier.object_identifier().end());
  der.insert(der.end(), algorithm_identifier.parameters().begin(),
             algorithm_identifier.parameters().end());

  // The fields of |algorithm_identifier| are wrapped around a sequence (RFC
  // 5280, 4.1.1.2).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der| subtracted by |tag_len_pos|
  // equates to the size of the value of |algorithm_identifier|.
  EncodeTagAndLength(0x30, der.size() - tag_len_pos, tag_len_pos, der);
}

template <>
void Encode<SubjectPublicKeyInfoSequence>(
    const SubjectPublicKeyInfoSequence& subject_public_key_info,
    std::vector<uint8_t>& der) {
  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der.size();

  Encode(subject_public_key_info.algorithm_identifier(), der);
  Encode(subject_public_key_info.subject_public_key(), der);

  // The fields of |subject_public_key_info| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der| subtracted by |tag_len_pos|
  // equates to the size of the value of |subject_public_key_info|.
  EncodeTagAndLength(0x30, der.size() - tag_len_pos, tag_len_pos, der);
}

template <>
void Encode<TimeChoice>(const TimeChoice& val, std::vector<uint8_t>& der) {
  // The |Time| field either has an UTCTime or a GeneralizedTime (RFC 5280, 4.1
  // & 4.1.2.5).
  if (val.has_utc_time()) {
    return Encode(val.utc_time(), der);
  }
  return Encode(val.generalized_time(), der);
}

template <>
void Encode<ValiditySequence>(const ValiditySequence& validity,
                              std::vector<uint8_t>& der) {
  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der.size();

  Encode(validity.not_before().value(), der);
  Encode(validity.not_after().value(), der);

  // The fields of |Validity| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der| subtracted by |tag_len_pos|
  // equates to the size of the value of |validity|.
  EncodeTagAndLength(0x30, der.size() - tag_len_pos, tag_len_pos, der);
}

template <>
void Encode<VersionNumber>(const VersionNumber& version,
                           std::vector<uint8_t>& der) {
  // |version| is Context-specific with tag number 0 (RFC 5280, 4.1 & 4.1.2.1).
  // Takes on values 0, 1 and 2, so only require length of 1 to
  // encode it (RFC 5280, 4.1 & 4.1.2.1).
  std::vector<uint8_t> derver_num = {0x80, 0x01, static_cast<uint8_t>(version)};
  der.insert(der.end(), derver_num.begin(), derver_num.end());
}

template <>
void Encode<TBSCertificateSequence>(
    const TBSCertificateSequence& tbs_certificate,
    std::vector<uint8_t>& der) {
  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der.size();

  Encode(tbs_certificate.version(), der);
  Encode(tbs_certificate.serial_number(), der);
  Encode(tbs_certificate.signature_algorithm(), der);
  Encode(tbs_certificate.issuer().name(), der);
  Encode(tbs_certificate.validity(), der);
  Encode(tbs_certificate.subject().name(), der);
  Encode(tbs_certificate.subject_public_key_info(), der);

  // Preserve to later backtrack and explicitly set tag.
  size_t pos_of_tag;
  // RFC 5280, 4.1: |issuer_unique_id| and |subject_unique_id|
  // are only set for v2 and v3 and |extensions| only set for v3.
  // However, set |issuer_unique_id|, |subject_unique_id|, and |extensions|
  // independently of the version number for interesting inputs.
  if (tbs_certificate.has_issuer_unique_id()) {
    pos_of_tag = der.size();
    Encode(tbs_certificate.issuer_unique_id().unique_identifier(), der);
    // |issuer_unqiue_id| is Context-specific with tag number 1 (RFC 5280, 4.1
    // & 4.1.2.8).
    SetTag(0x81, pos_of_tag, der);
  }
  if (tbs_certificate.has_subject_unique_id()) {
    pos_of_tag = der.size();
    Encode(tbs_certificate.subject_unique_id().unique_identifier(), der);
    // |subject_unqiue_id| is Context-specific with tag number 2 (RFC 5280, 4.1
    // & 4.1.2.8).
    SetTag(0x82, pos_of_tag, der);
  }
  if (tbs_certificate.has_extensions()) {
    pos_of_tag = der.size();
    Encode(tbs_certificate.extensions(), der);
    // |extensions| is Context-specific with tag number 3 (RFC 5280, 4.1
    // & 4.1.2.8).
    SetTag(0x83, pos_of_tag, der);
  }

  // The fields of |tbs_certificate| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der| subtracted by |tag_len_pos|
  // equates to the size of the value of |tbs_certificate|.
  EncodeTagAndLength(0x30, der.size() - tag_len_pos, tag_len_pos, der);
}

template <typename T>
void Encode(const T& t, std::vector<uint8_t>& der) {
  if (t.has_pdu()) {
    Encode(t.pdu(), der);
    return;
  }
  Encode(t.value(), der);
}

std::vector<uint8_t> X509CertificateToDER(
    const X509Certificate& X509_certificate) {
  // Contains DER encoded X509 Certificate.
  std::vector<uint8_t> der;

  // Save the current size in |tag_len_pos| to place sequence tag and length
  // after the value is encoded.
  size_t tag_len_pos = der.size();

  Encode(X509_certificate.tbs_certificate(), der);
  Encode(X509_certificate.signature_algorithm(), der);
  Encode(X509_certificate.signature_value(), der);

  // The fields of |X509_certificate| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is constructed and has tag number 16 (X.208, Table 1).
  // The current size of |der| subtracted by |tag_len_pos|
  // equates to the size of the value of |X509_certificate|.
  EncodeTagAndLength(0x30, der.size() - tag_len_pos, tag_len_pos, der);
  return der;
}

}  // namespace x509_certificate