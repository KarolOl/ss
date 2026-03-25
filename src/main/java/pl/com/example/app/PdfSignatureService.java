package pl.com.example.app;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XAdESOCSPSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class PdfSignatureService {

    public Reports verifySignature(String pdfFilePath) {
        FileDocument document = new FileDocument(pdfFilePath);
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();

        // OCSP + CRL online (dss-service)
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        ocspSource.setDataLoader(new CommonsDataLoader());
        verifier.setOcspSource(ocspSource);

        OnlineCRLSource crlSource = new OnlineCRLSource();
        crlSource.setDataLoader(new CommonsDataLoader());
        verifier.setCrlSource(crlSource);

        CommonTrustedCertificateSource trustedStore = new CommonTrustedCertificateSource();
        trustedStore.addCertificate(validator.getSignatures().get(0).getSigningCertificateToken()); // tu dodajesz swój cert jako TRUSTED_STORE[web:160][web:164]
        verifier.setTrustedCertSources(trustedStore);

// 1. FileCacheDataLoader = DSSFileLoader (dss-service)
        FileCacheDataLoader dataLoader = new FileCacheDataLoader();
        dataLoader.setCacheExpirationTime(24 * 60 * 60 * 1000L); // 24h cache

        // 2. TSL Job
        TLValidationJob tlJob = new TLValidationJob();
        TrustedListsCertificateSource tlSource = new TrustedListsCertificateSource();
        LOTLSource lotl = new LOTLSource();
        lotl.setUrl("https://ec.europa.eu/tools/lotl/eu-lotl.xml");
        lotl.setLotlPredicate(TLPredicateFactory.createEULOTLPredicate());

        tlJob.setTrustedListCertificateSource(tlSource);
        tlJob.setOnlineDataLoader(dataLoader); // DSSFileLoader OK!
        tlJob.setListOfTrustedListSources(lotl);

        tlJob.onlineRefresh(); // EU LOTL loaded
        validator.setCertificateVerifier(verifier);

        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        StringBuilder result = new StringBuilder("=== WERYFIKACJA PODPISU KWALIFIKOWANEGO ===\n");
        result.append(String.format("Podpisy: %d\n", simpleReport.getSignaturesCount()));
        result.append(String.format("Ważne: %d\n\n", simpleReport.getValidSignaturesCount()));
        int i = 0;
        // Iteracja po podpisach
        for (String signatureId : simpleReport.getSignatureIdList()) {
            i++;
            Indication indication = simpleReport.getIndication(signatureId);
            result.append(String.format("- Podpis %d:\n", i + 1));
            result.append(String.format("  ID: %s\n", signatureId));
            result.append(String.format("  Status: %s\n", indication));
            result.append(String.format("  Format: %s\n", simpleReport.getSignatureFormat(signatureId)));
            result.append(String.format("  Cert CN: %s\n\n",
                    diagnosticData.getSigningCertificateId(signatureId)));
        }

        result.append("SimpleReport XML:\n").append(reports.getXmlSimpleReport());
        return reports;

    }

    public boolean isSignatureValid(String pdfFilePath) {
        try {
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(pdfFilePath));
            validator.setCertificateVerifier(new CommonCertificateVerifier());
            Reports reports = validator.validateDocument();
            SimpleReport simpleReport = reports.getSimpleReport();

            return simpleReport.getSignaturesCount() > 0 &&
                    simpleReport.getValidSignaturesCount() > 0;
        } catch (Exception e) {
            return false;
        }
    }
}
