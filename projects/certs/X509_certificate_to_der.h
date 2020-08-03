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

template <typename T>
void Encode(const T& t, std::vector<uint8_t>& der);

// Encode(FIELD) DER encodes the field found in X509 Certificates
// and writes the results to |der_|.
template <>
void Encode<TBSCertificateSequence>(
    const TBSCertificateSequence& tbs_certificate,
    std::vector<uint8_t>& der);
template <>
void Encode<VersionNumber>(const VersionNumber& version,
                           std::vector<uint8_t>& der);
template <>
void Encode<ValiditySequence>(const ValiditySequence& validity,
                              std::vector<uint8_t>& der);
template <>
void Encode<TimeChoice>(const TimeChoice& val, std::vector<uint8_t>& der);
template <>
void Encode<SubjectPublicKeyInfoSequence>(
    const SubjectPublicKeyInfoSequence& subject_public_key_info,
    std::vector<uint8_t>& der);
template <>
void Encode<AlgorithmIdentifier>(
    const AlgorithmIdentifier& algorithm_identifier,
    std::vector<uint8_t>& der);
template <>
void Encode<asn1_pdu::PDU>(const asn1_pdu::PDU& pdu, std::vector<uint8_t>& der);

}  // namespace x509_certificate

#endif