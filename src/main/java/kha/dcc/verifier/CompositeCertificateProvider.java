package kha.dcc.verifier;

import se.digg.dgc.signatures.CertificateProvider;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class CompositeCertificateProvider implements CertificateProvider {

    List<CertificateProvider> certificateProviders;

    public CompositeCertificateProvider(List<CertificateProvider> certificateProviders) {
        this.certificateProviders = certificateProviders;
    }

    @Override
    public List<X509Certificate> getCertificates(String country, byte[] kid) {
        return certificateProviders.stream()
                .map(cp -> cp.getCertificates(country, kid))
                .flatMap(Collection::stream)
                .collect(toList());
    }
}
