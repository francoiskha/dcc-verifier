package kha.dcc.verifier;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.digg.dgc.signatures.CertificateProvider;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import static java.util.stream.Collectors.toList;

public class HardCodedCertificateProvider implements CertificateProvider {

    private static final Logger log = LoggerFactory.getLogger(HardCodedCertificateProvider.class);

    // Test key from https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/FR/2DCode/raw/DCC_Test_0001.json
    public static List<String> certificates = List.of(
            "MIID3zCCAcegAwIBAgIIQ0z45mUGHbswDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCRlIxHTAbBgNVBAoTFElNUFJJTUVSSUUgTkFUSU9OQUxFMR4wHAYDVQQLExVGT1IgVEVTVCBQVVJQT1NFIE9OTFkxGDAWBgNVBAMTD0lOR1JPVVBFIERTYyBDQTAeFw0yMTA1MDcxNzIwMDBaFw0yMTA4MDcxNzIwMDBaMGgxCzAJBgNVBAYTAkZSMR0wGwYDVQQKExRJTVBSSU1FUklFIE5BVElPTkFMRTEeMBwGA1UECxMVRk9SIFRFU1QgUFVSUE9TRSBPTkxZMRowGAYDVQQDExFJTkdST1VQRSBEU0MgMDAwMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL//HMQ3H0KXjdP0VAxSTb79g5dL1/8vfHaJJ2n6mmSYdJseOFsOTbqb3lt5n7Yclufb5hOY2BrRhclIY1s8NG+jWjBYMAkGA1UdEwQCMAAwHQYDVR0OBBYEFK2L3nmo5HPXC39xg18jpjfhg8K+MB8GA1UdIwQYMBaAFGC6GE5ZcxNozst1TALlODiYzop4MAsGA1UdDwQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEABbhiiE3Er+w02p/BYlkdrjDn4ppWp1jVovjuldJ3CbBx+P1FfXFFJDrvSarEeZJN9H5QXeJoO8PcQnqaTgCyChOCT8sSzonoCoKK54UJXnTPufbkmeLeLctoKNywJnaOzvZcYKX4SiO/HnSjSYjMeLLeg081RaQW6zRLGHRm07b3INCm80X35U4F7V6OdoO6eOR64yrkTCvtuvcJhPbCRYgIWKKVh7Alo/q7y/v48j+7kc0jHpaiHUyjDN6gAAapMOjU9kxNOY94ITrw+TF0YXfhj2oEGzbFdsFQ/M/o/F787bg62xLkST+60ehS88Le6tMQuFJiZ1Krhseo6wDK/spyRhuMV/QB9kM/VrC9kUHjXi7z3bWawF8DeyYq1fHbkmn4CwSzG2dmNv8rf+WYogeW+QRt3XfcuItSRdMLcG2iffbLubb7bSp1NbYKou+D+8ryFzMc3CvnLUKKHv6NzKgzIze7mkFUE5HTPwM8VhoboOos6cmfAVJ2eTq41e0OgeSzM9aAxQNlEeeOHINsKaG8ylRm7rfBlTNO+rsYSWqQQulmYEfUIyOVoq+FjCRIKTFKRuOatjkn9+rx98P6gfeed7LUamtqDLjCXJIQSUX1EuLCHr9IlUdCR5+6wC+Ylpikb/74JyZ7rfDIxbjSWJK+su5Jq95F2soydAtto5A="
    );

    @Override
    public List<X509Certificate> getCertificates(String country, byte[] kid) {
        return certificates.stream().map(base64EncodedCertificate -> {
            try {
                byte[] bytes = Base64.decode(base64EncodedCertificate);
                return (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(bytes));
            } catch (CertificateException e) {
                log.error("Can't parse X509 Certificate {}", base64EncodedCertificate, e);
                return null;
            }
        }).filter(Objects::nonNull)
                .collect(toList());
    }
}
