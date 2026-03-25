package pl.com.example.app;

import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class PdfSignatureVerificationServiceTest {

    @Autowired
    private PdfSignatureService service;

    @Test
    void shouldVerifyQualifiedSignature() throws IOException {
        // Zakładamy, że masz przykładowy signed PDF w src/test/resources/signed-qualified.pdf
        // Możesz wygenerować go używając DSS demo lub narzędzi eIDAS

        var reports = service.verifySignature("src/test/resources/niepodpisany_dokument.pdf.xml");

        // Sprawdza czy podpis jest VALID (dla qualified signature oczekujemy TOTAL_PASSED)
        assertThat(reports).isEqualTo("TOTAL_PASSED");
    }

}