package pl.com.example.app;

import eu.europa.esig.dss.validation.reports.Reports;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * Kontroler REST do weryfikacji podpisów elektronicznych.
 * 
 * Umożliwia weryfikację podpisów typu detached (np. XAdES) oraz podpisów osadzonych (np. PDF/PAdES).
 * 
 * Endpointy:
 * <ul>
 *   <li><b>POST /api/verify</b> - Weryfikuje podpis elektroniczny. Obsługuje zarówno podpisy osadzone, jak i detached.</li>
 * </ul>
 *
 * Parametry:
 * <ul>
 *   <li><b>signedFile</b> (MultipartFile, wymagany) - Plik podpisany (oryginalny dokument).</li>
 *   <li><b>signature</b> (MultipartFile, opcjonalny) - Plik z podpisem detached (np. XAdES). Jeśli nie podano, zakładana jest weryfikacja podpisu osadzonego.</li>
 * </ul>
 *
 * Przykład użycia (curl):
 * <pre>
 * curl -X POST http://localhost:8080/api/verify \
 *   -F "signedFile=@/ścieżka/do/dokumentu.pdf" \
 *   -F "signature=@/ścieżka/do/podpisu.xades" # parametr signature jest opcjonalny
 * </pre>
 *
 * Zwraca: XML z raportem walidacji podpisu.
 */
@RestController
@RequestMapping("/api/verify")
public class SignatureVerificationController {

    private final SignatureVerificationService verificationService;

    public SignatureVerificationController(SignatureVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @PostMapping
    public ResponseEntity<String> verifySignature(
            @RequestParam(value = "signature", required = false) MultipartFile detachedSignature,
            @RequestParam("signedFile") MultipartFile signedFile) {
            Reports reports = verificationService.verifySignature(signedFile, detachedSignature);
            return ResponseEntity.ok(reports.getXmlValidationReport());
    }

    @PostMapping("/pdf")
    public ResponseEntity<byte[]> verifySignaturePdf(
            @RequestParam(value = "signature", required = false) MultipartFile detachedSignature,
            @RequestParam("signedFile") MultipartFile signedFile) {
        byte[] pdf = verificationService.verifyDetachedSignatureAsPdf(signedFile, detachedSignature);
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=signature-report.pdf")
                .header("Content-Type", "application/pdf")
                .body(pdf);
    }
}
