package kha.dcc.verifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import se.digg.dgc.service.DGCDecoder;
import se.digg.dgc.service.impl.DefaultDGCDecoder;
import se.digg.dgc.signatures.CertificateProvider;
import se.digg.dgc.signatures.DGCSignatureVerifier;
import se.digg.dgc.signatures.impl.DefaultDGCSignatureVerifier;

import java.text.ParseException;
import java.util.List;

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
    CertificateProvider certificateProvider(
            @Value("${trustListEndpointUrl}") String trustListEndpointUrl
    ) throws ParseException {
	    return new CompositeCertificateProvider(List.of(
                new HardCodedCertificateProvider(),
                new DgcTrustPointCertificateProvider(trustListEndpointUrl)
        ));
    }
}
