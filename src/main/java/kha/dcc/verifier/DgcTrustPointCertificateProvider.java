package kha.dcc.verifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import se.digg.dgc.signatures.CertificateProvider;
import se.digg.dgc.signatures.impl.DefaultDGCSignatureVerifier;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.*;

import static java.util.stream.Collectors.toList;

/**
 * Format documentation : https://github.com/DIGGSweden/dgc-trust/blob/main/specifications/trust-list.md
 */
public class DgcTrustPointCertificateProvider implements CertificateProvider {

    private static final Logger log = LoggerFactory.getLogger(DefaultDGCSignatureVerifier.class);

    private final String trustListEndpointUrl;
    private final List<CertHolder> certificates;

    public DgcTrustPointCertificateProvider(String trustListEndpointUrl) throws ParseException {
        this.trustListEndpointUrl = trustListEndpointUrl;
        certificates = loadCertificates();
    }

    @Override
    public List<X509Certificate> getCertificates(String country, byte[] kid) {
        // Very ineficient, must change the holder for an implementation with O(1) access
        List<X509Certificate> result = List.of();
        if (kid != null)
            result = certificates.stream()
                    .filter(certificate -> Arrays.equals(kid, certificate.getKid()))
                    .findFirst()
                    .map(CertHolder::getCertificate)
                    .stream()
                    .collect(toList());
        if (result.isEmpty() && country != null && !country.isBlank()) {
            result = certificates.stream()
                    .filter(certificate -> country.trim().equalsIgnoreCase(certificate.getCountry()))
                    .map(CertHolder::getCertificate)
                    .collect(toList());
        }
        if (result.isEmpty()) {
            result = certificates.stream()
                    .map(CertHolder::getCertificate)
                    .collect(toList());
        }
        return result;

    }

    static class CertHolder {
        String country;
        byte[] kid;
        X509Certificate certificate;

        public CertHolder(String country, byte[] kid, String base64EncodedCertificate) {
            this.country = country;
            this.kid = kid;
            try {
                byte[] bytes = Base64.decode(base64EncodedCertificate);
                this.certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(bytes));
            } catch (CertificateException e) {
                log.error("Can't instanciate X509 Certificate holder for " + country, e);
            }
        }

        public CertHolder(String country, byte[] kid, X509Certificate x509Certificate) {
            this.country = country;
            this.kid = kid;
            this.certificate = x509Certificate;
        }

        public String getCountry() {
            return country;
        }

        public byte[] getKid() {
            return kid;
        }

        public X509Certificate getCertificate() {
            return certificate;
        }
    }


    public List<CertHolder> loadCertificates() throws ParseException {
        // No signature check for now
        ResponseEntity<String> response = new RestTemplate().getForEntity(trustListEndpointUrl, String.class);
        JWSObject jwsObject = JWSObject.parse(Objects.requireNonNull(response.getBody()));
        Map<String, Object> jwsPayload = jwsObject.getPayload().toJSONObject();
        JSONObject dscTrustList = (JSONObject) jwsPayload.get("dsc_trust_list");
        return dscTrustList.keySet().stream()
                .map(countryCode -> ((JSONArray) ((JSONObject) dscTrustList.get(countryCode)).get("keys")).stream().map(jsonJwk -> getCertHolder(countryCode, (JSONObject) jsonJwk))
                        .filter(Objects::nonNull)
                        .collect(toList()))
                .flatMap(Collection::stream)
                .collect(toList());
    }

    private CertHolder getCertHolder(String countryCode, JSONObject jsonJwk) {
        try {
            JWK jwk = JWK.parse(jsonJwk);
            if(jwk.getParsedX509CertChain().size() > 1) {
                log.warn("there is more than 1 x509 certfiicate for {} {}", countryCode, jsonJwk.get("kid"));
            }
            X509Certificate x509Certificate = jwk.getParsedX509CertChain().stream().findFirst().orElse(null);
            return new CertHolder(countryCode, jwk.getKeyID().getBytes(StandardCharsets.UTF_8), x509Certificate);
        } catch (ParseException e) {
            log.error("cannot parse JWK for {} {}", countryCode, jsonJwk.get("kid"), e);
            return null;
        }
    }
}
