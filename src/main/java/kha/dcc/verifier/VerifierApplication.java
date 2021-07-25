package kha.dcc.verifier;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import se.digg.dgc.service.DGCDecoder;
import se.digg.dgc.service.impl.DefaultDGCDecoder;
import se.digg.dgc.signatures.CertificateProvider;
import se.digg.dgc.signatures.DGCSignatureVerifier;
import se.digg.dgc.signatures.impl.DefaultDGCSignatureVerifier;

@SpringBootApplication
public class VerifierApplication {

	public static void main(String[] args) {
		SpringApplication.run(VerifierApplication.class, args);
	}

	@Bean
    DGCDecoder dgcDecoder(final DGCSignatureVerifier dgcSignatureVerifier, final CertificateProvider certificateProvider){
	    return new DefaultDGCDecoder(dgcSignatureVerifier, certificateProvider);
    }
	
    @Bean
    DGCSignatureVerifier dgcSignatureVerifier() {
	    return  new DefaultDGCSignatureVerifier();
    }

    @Bean
    CertificateProvider certificateProvider() {
        return  new HardCodedCertificateProvider();
    }
}
