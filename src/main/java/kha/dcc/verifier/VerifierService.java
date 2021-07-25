package kha.dcc.verifier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import se.digg.dgc.payload.v1.DGCSchemaException;
import se.digg.dgc.payload.v1.DigitalCovidCertificate;
import se.digg.dgc.service.DGCDecoder;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;

@Service
@RestController
@RequestMapping("/dcc")
public class VerifierService {

    DGCDecoder dgcDecoder;

    @Autowired
    public VerifierService(DGCDecoder dgcDecoder) {
        this.dgcDecoder = dgcDecoder;
    }

    @PostMapping("/verify")
    public DigitalCovidCertificate verify(String base45EncodedDcc) throws CertificateExpiredException, SignatureException, IOException, DGCSchemaException {
        return dgcDecoder.decode(base45EncodedDcc);
    }

}