package kha.dcc.verifier;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.digg.dgc.signatures.CertificateProvider;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

public class HardCodedCertificateProvider implements CertificateProvider {

    private static final Logger log = LoggerFactory.getLogger(HardCodedCertificateProvider.class);


    public static List<CertHolder> certificates = List.of(
            new CertHolder("FR", Base64.decode("fGLuvg6n5wk=".getBytes(StandardCharsets.UTF_8)), "MIIEGzCCAgOgAwIBAgIUNWO7+/2lmGQGT1cep5petfsOFocwDQYJKoZIhvcNAQELBQAwMjELMAkGA1UEBhMCRlIxDTALBgNVBAoMBEdvdXYxFDASBgNVBAMMC0NTQ0EtRlJBTkNFMB4XDTIxMDYxNDIyMDAwMFoXDTIzMDYxNDIyMDAwMFowRTELMAkGA1UEBhMCRlIxDTALBgNVBAoMBENOQU0xEjAQBgNVBAsMCTE4MDAzNTAyNDETMBEGA1UEAwwKRFNDX0ZSXzAxOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCJiBWroM8AeX/1cn0Nyk300qLpMAD1UoB2Vq7a3No+BbgFKcPzm0ZwPaQYzfx3VHNc3JfUjv77AhJx5F4cY8+GjgeAwgd0wHQYDVR0OBBYEFF6mKwOiAheaIxTCkdVKd8zgd7urMB8GA1UdIwQYMBaAFL6KLtbJ+SBOOicDCJdN7P3ZfcXmMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMC0GA1UdHwQmMCQwIqAgoB6GHGh0dHA6Ly9hbnRzLmdvdXYuZnIvY3NjYV9jcmwwGAYDVR0gBBEwDzANBgsqgXoBgUgfAwkBATA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAKGGGh0dHBzOi8vYW50LmdvdXYuZnIvY3NjYTANBgkqhkiG9w0BAQsFAAOCAgEAu8BaLZXFj9/e2/a59mBrOhY2m5SpcAoayxF3zOkIOt7LNX0QqHuomOyGLHMnAhNALgS2vhDXD0hhs96ZcKaystlMePpYsVRyaYa53GwMrGHiLwFxH5qQNClCcktAP++wCcdQXzTyZOn9/GNdmquW1PNMLPCEfqlnzWawdpITr+CYMXa9R5BEMmdX19F41HcoPRn9/X2uHW/ONmBywTwJ3s0U8F5HF21buZtxVDvX4ey+qINBru4MiGwgRCsklS9kDbl3ODUox0lwhs2VgQzqjALF4xYgsdN2LJezrwAiL8GMRAenmX9eDdgzMGnjKFT6yW8BCrPsyUnM15RAou3BrwIp6oxXHnR8wbeKG7pzZZY1J4zk4yYyihwxguWbUZGksJsNAQoNdNHBZtc8a7Oj5onLyUIetd7ELXxdk8uy7WVFeye5V8qJRhWrFyhWWFscQeY8GktefXiGEh6fxGfRU5R5b0PznxfMiA3olad3s17dr+jzqCM/hcY2FmUTjYrSrAyrhHdmCYIJ3US71If74UeMs6NZnQRRiu3tbAX+TiDOHsEHEIOHldbyQqFfclyiC26fHTqcNfIAxXPmPDQ1jpEmhRjFDlOWHoSnzsGZi/wa1kmSb6+2uHgUP/C/O2oi+yAk8GpwpEi8Sgv+HH/p7z0ympQK8IUOG/4K3/urdto=")
    );

    @Override
    public List<X509Certificate> getCertificates(String country, byte[] kid) {
        return List.of(certificates.get(0).certificate);
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
                log.error("Can't instanciate X509 Certificate holder", e);
            }
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
}
