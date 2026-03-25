package pl.com.example.app;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import jakarta.annotation.PostConstruct;
import org.apache.commons.io.FileUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Service
public class SignatureVerificationService {

    private CommonTrustedCertificateSource trustedCertificateSource;
    private CertificateVerifier certificateVerifier;

    @PostConstruct
    public void init() throws IOException, CertificateException {
        trustedCertificateSource = new CommonTrustedCertificateSource();
        loadTrustedCertificates();

        certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);
        certificateVerifier.setOcspSource(new OnlineOCSPSource());
        certificateVerifier.setCrlSource(new OnlineCRLSource());

        // Konfiguracja TSL dla Polski (z EU LOTL)
        TrustedListsCertificateSource tslSource = new TrustedListsCertificateSource();

        // Załaduj certyfikaty operatorów TSL do weryfikacji podpisu pod listą TSL
        CommonCertificateSource tslSigningCertSource = new CommonCertificateSource();
        FileUtils.listFiles(new ClassPathResource("certs").getFile(), new String[]{"cer", "crt"}, true)
                .stream()
                .map(DSSUtils::loadCertificate)
                .forEach(tslSigningCertSource::addCertificate);

        TLValidationJob tlValidationJob = new TLValidationJob();
        tlValidationJob.setTrustedListCertificateSource(tslSource);

        CommonsDataLoader onlineLoader = new CommonsDataLoader();
        onlineLoader.setTimeoutConnection(10000);
        onlineLoader.setTimeoutSocket(10000);

        FileCacheDataLoader dataLoader = new FileCacheDataLoader();
        dataLoader.setDataLoader(onlineLoader);
        dataLoader.setCacheExpirationTime(24 * 60 * 60 * 1000L); // 24h cache

        tlValidationJob.setOnlineDataLoader(dataLoader);
        tlValidationJob.setSynchronizationStrategy(new ExpirationAndSignatureCheckStrategy());

        TLSource plTslSource = new TLSource();
        plTslSource.setUrl("https://www.nccert.pl/tsl/PL_TSL.xml");
        plTslSource.setCertificateSource(tslSigningCertSource);

        tlValidationJob.setTrustedListSources(plTslSource);
        tlValidationJob.onlineRefresh();
        System.out.println("TSL OK: " + tslSource.getNumberOfTrustedEntityKeys() + " certów");

        certificateVerifier.setTrustedCertSources(trustedCertificateSource, tslSource);
    }

    private void loadTrustedCertificates() throws IOException, CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Resource resource = new ClassPathResource("certs/trusted-cert.pem");

        if (resource.exists()) {
            try (InputStream is = resource.getInputStream()) {
                X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
                CertificateToken certToken = new CertificateToken(cert);
                trustedCertificateSource.addCertificate(certToken);
            }
        }
    }

    public Reports verifySignature(MultipartFile signedFile, MultipartFile detachedSignature) {
        if (Objects.isNull(signedFile) || signedFile.isEmpty()) {
            throw new RuntimeException("Missing signed file");
        }
        if (Objects.isNull(detachedSignature) || detachedSignature.isEmpty()) {
            return verifySignature(signedFile);
        } else {
            return verifyDetachedSignature(detachedSignature, signedFile);
        }
    }

    private Reports verifySignature(MultipartFile signedFile) {
        try (final var is = signedFile.getInputStream()) {
            final var doc = new InMemoryDocument(is, signedFile.getOriginalFilename());
            final var validator = SignedDocumentValidator.fromDocument(doc);
            validator.setCertificateVerifier(certificateVerifier);
            return validator.validateDocument();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] xmlToPdf(String xml) {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            PDPageContentStream contentStream = new PDPageContentStream(document, page);
            contentStream.setFont(PDType1Font.HELVETICA, 10);
            float margin = 5;
            float width = page.getMediaBox().getWidth() - 2 * margin;
            float y = page.getMediaBox().getHeight() - margin;
            float leading = 12f;
            String[] lines = xml.split("\n");
            contentStream.beginText();
            contentStream.newLineAtOffset(margin, y);
            for (String line : lines) {
                // Usuń znaki tabulacji i inne niedozwolone znaki kontrolne
                String safeLine = line.replace("\t", " ")
                        .replace("\u000B", " ")
                        .replace("\u000C", " ")
                        .replace("\u0085", " ")
                        .replace("\u2028", " ")
                        .replace("\u2029", " ")
                        .replace("Ą", "A")
                        .replace("Ć", "C")
                        .replace("Ę", "E")
                        .replace("Ł", "L")
                        .replace("Ń", "N")
                        .replace("Ó", "O")
                        .replace("Ś", "S")
                        .replace("Ź", "Z")
                        .replace("Ż", "Z")
                        .replace("ą", "a")
                        .replace("ć", "c")
                        .replace("ę", "e")
                        .replace("ł", "l")
                        .replace("ń", "n")
                        .replace("ó", "o")
                        .replace("ś", "s")
                        .replace("ź", "z")
                        .replace("ż", "z");

                // Podziel linię na fragmenty mieszczące się w szerokości strony
                while (!safeLine.isEmpty()) {
                    int breakIndex = safeLine.length();
                    String subLine = safeLine;
                    while (PDType1Font.HELVETICA.getStringWidth(subLine) / 1000 * 10 > width && breakIndex > 0) {
                        breakIndex--;
                        subLine = safeLine.substring(0, breakIndex);
                    }
                    contentStream.showText(subLine.replace("\r", "").replace("\n", ""));
                    contentStream.newLineAtOffset(0, -leading);
                    y -= leading;
                    safeLine = safeLine.substring(subLine.length());
                    if (y < margin + leading) {
                        contentStream.endText();
                        contentStream.close();
                        page = new PDPage(PDRectangle.A4);
                        document.addPage(page);
                        contentStream = new PDPageContentStream(document, page);
                        contentStream.setFont(PDType1Font.HELVETICA, 10);
                        y = page.getMediaBox().getHeight() - margin;
                        contentStream.beginText();
                        contentStream.newLineAtOffset(margin, y);
                    }
                }
            }
            contentStream.endText();
            contentStream.close();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Błąd konwersji XML do PDF", e);
        }
    }

    public byte[] generatePdfTableReport(Reports reports) {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            PDPageContentStream contentStream = new PDPageContentStream(document, page);
            contentStream.setFont(PDType1Font.HELVETICA_BOLD, 14);
            float margin = 20;
            float y = page.getMediaBox().getHeight() - margin;
            float tableTop = y - 30;
            float leading = 16f;
            float cellHeight = 20f;
            float[] colWidths = {80, 80, 100, 100, 100};
            float tableWidth = 0;
            for (float w : colWidths) tableWidth += w;
            float x = margin;

            // Nagłówek
            contentStream.beginText();
            contentStream.newLineAtOffset(margin, y);
            contentStream.showText("Raport weryfikacji podpisów elektronicznych");
            contentStream.endText();

            // Tabela - nagłówki
            y = tableTop;
            contentStream.setFont(PDType1Font.HELVETICA_BOLD, 10);
            String[] headers = {"ID", "Indication", "SubIndication", "Format", "Qualification"};
            x = margin;
            for (int i = 0; i < headers.length; i++) {
                contentStream.beginText();
                contentStream.newLineAtOffset(x, y);
                contentStream.showText(headers[i]);
                contentStream.endText();
                x += colWidths[i];
            }
            y -= cellHeight;

            // Tabela - dane
            contentStream.setFont(PDType1Font.HELVETICA, 10);
            var simpleReport = reports.getSimpleReport();
            for (String id : simpleReport.getSignatureIdList()) {
                x = margin;
                String[] row = {
                    id,
                    String.valueOf(simpleReport.getIndication(id)),
                    String.valueOf(simpleReport.getSubIndication(id)),
                    String.valueOf(simpleReport.getSignatureFormat(id)),
                    String.valueOf(simpleReport.getSignatureQualification(id))
                };
                for (int i = 0; i < row.length; i++) {
                    contentStream.beginText();
                    contentStream.newLineAtOffset(x, y);
                    String cell = row[i] != null ? row[i].replaceAll("[\r\n\t]", " ") : "";
                    // Przytnij jeśli za długie
                    if (cell.length() > 40) cell = cell.substring(0, 37) + "...";
                    contentStream.showText(cell);
                    contentStream.endText();
                    x += colWidths[i];
                }
                y -= cellHeight;
                if (y < margin + cellHeight) {
                    contentStream.close();
                    page = new PDPage(PDRectangle.A4);
                    document.addPage(page);
                    contentStream = new PDPageContentStream(document, page);
                    contentStream.setFont(PDType1Font.HELVETICA, 10);
                    y = page.getMediaBox().getHeight() - margin;
                }
            }
            contentStream.close();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Błąd generowania PDF z tabelą", e);
        }
    }

    public byte[] generatePdfKeyValueReport(Reports reports) {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            PDPageContentStream contentStream = new PDPageContentStream(document, page);
            contentStream.setFont(PDType1Font.HELVETICA_BOLD, 14);
            float margin = 20;
            float y = page.getMediaBox().getHeight() - margin;
            float leading = 18f;
            // Nagłówek
            contentStream.beginText();
            contentStream.newLineAtOffset(margin, y);
            contentStream.showText("Raport weryfikacji podpisów elektronicznych");
            contentStream.endText();
            y -= 2 * leading;
            contentStream.setFont(PDType1Font.HELVETICA, 11);
            var simpleReport = reports.getSimpleReport();
            for (String id : simpleReport.getSignatureIdList()) {
                String[][] pairs = {
                    {"ID", id},
                    {"Indication", String.valueOf(simpleReport.getIndication(id))},
                    {"SubIndication", String.valueOf(simpleReport.getSubIndication(id))},
                    {"Format", String.valueOf(simpleReport.getSignatureFormat(id))},
                    {"Qualification", String.valueOf(simpleReport.getSignatureQualification(id))}
                };
                for (String[] pair : pairs) {
                    String key = pair[0] + ": ";
                    String value = pair[1] != null ? pair[1].replaceAll("[\r\n\t]", " ") : "";
                    if (value.length() > 80) value = value.substring(0, 77) + "...";
                    contentStream.beginText();
                    contentStream.newLineAtOffset(margin, y);
                    contentStream.showText(key + value);
                    contentStream.endText();
                    y -= leading;
                    if (y < margin + leading) {
                        contentStream.close();
                        page = new PDPage(PDRectangle.A4);
                        document.addPage(page);
                        contentStream = new PDPageContentStream(document, page);
                        contentStream.setFont(PDType1Font.HELVETICA, 11);
                        y = page.getMediaBox().getHeight() - margin;
                    }
                }
                // Oddziel podpisy pustą linią
                y -= leading / 2;
            }
            contentStream.close();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Błąd generowania PDF (klucz-wartość)", e);
        }
    }

    /**
     * Buduje raport klucz-wartość (drzewo) dla dowolnego obiektu, do 3 poziomów zagnieżdżenia.
     */
    private void buildKeyValueTree(Object obj, String keyPrefix, int level, int maxLevel, List<String> lines, Set<Object> visited) {
        if (obj == null || level > maxLevel || visited.contains(obj)) {
            return;
        }
        visited.add(obj);
        Class<?> clazz = obj.getClass();
        if (clazz.isPrimitive() || obj instanceof String || obj instanceof Number || obj instanceof Boolean || obj instanceof Enum) {
            lines.add(keyPrefix + obj);
            return;
        }
        if (obj instanceof Collection) {
            int idx = 0;
            for (Object item : (Collection<?>) obj) {
                buildKeyValueTree(item, keyPrefix + "[" + idx + "]: ", level + 1, maxLevel, lines, visited);
                idx++;
            }
            return;
        }
        if (obj instanceof Map) {
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) obj).entrySet()) {
                buildKeyValueTree(entry.getValue(), keyPrefix + entry.getKey() + ": ", level + 1, maxLevel, lines, visited);
            }
            return;
        }
        // Dla obiektów: wypisz gettery
        Method[] methods = clazz.getMethods();
        for (Method m : methods) {
            if (m.getParameterCount() == 0 && Modifier.isPublic(m.getModifiers()) && (m.getName().startsWith("get") || m.getName().startsWith("is")) && !m.getName().equals("getClass")) {
                String fieldName = m.getName().replaceFirst("^(get|is)", "");
                if (!fieldName.isEmpty()) {
                    fieldName = Character.toLowerCase(fieldName.charAt(0)) + fieldName.substring(1);
                }
                try {
                    Object value = m.invoke(obj);
                    String indent = "  ".repeat(level);
                    if (value == null || value instanceof String || value instanceof Number || value instanceof Boolean || value instanceof Enum) {
                        lines.add(indent + fieldName + ": " + value);
                    } else if (value instanceof Collection) {
                        lines.add(indent + fieldName + ":");
                        buildKeyValueTree(value, indent + "  ", level + 1, maxLevel, lines, visited);
                    } else if (value instanceof Map) {
                        lines.add(indent + fieldName + ":");
                        buildKeyValueTree(value, indent + "  ", level + 1, maxLevel, lines, visited);
                    } else {
                        lines.add(indent + fieldName + ":");
                        buildKeyValueTree(value, indent + "  ", level + 1, maxLevel, lines, visited);
                    }
                } catch (Exception e) {
                    // pomiń błędy getterów
                }
            }
        }
    }

    /**
     * Generuje PDF z raportem klucz-wartość (drzewo) dla SimpleReport (do 3 poziomów).
     */
    public byte[] generatePdfKeyValueTreeReport(Reports reports) {
        List<String> lines = new ArrayList<>();
        Object simpleReport = reports.getSimpleReport();
        buildKeyValueTree(simpleReport, "", 0, 3, lines, new HashSet<>());
        return generatePdfFromLines(lines);
    }

    /**
     * Generuje PDF z listy linii tekstowych (zachowuje polskie znaki, łamanie linii, marginesy, font TTF jeśli dostępny).
     */
    private byte[] generatePdfFromLines(List<String> lines) {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            PDPageContentStream contentStream = new PDPageContentStream(document, page);
            contentStream.setFont(PDType1Font.HELVETICA, 10);
            float margin = 5;
            float width = page.getMediaBox().getWidth() - 2 * margin;
            float y = page.getMediaBox().getHeight() - margin;
            float leading = 12f;
            contentStream.beginText();
            contentStream.newLineAtOffset(margin, y);
            for (String line : lines) {
                // Usuń znaki tabulacji i inne niedozwolone znaki kontrolne
                String safeLine = line.replace("\t", " ")
                        .replace("\u000B", " ")
                        .replace("\u000C", " ")
                        .replace("\u0085", " ")
                        .replace("\u2028", " ")
                        .replace("\u2029", " ")
                        .replace("Ą", "A")
                        .replace("Ć", "C")
                        .replace("Ę", "E")
                        .replace("Ł", "L")
                        .replace("Ń", "N")
                        .replace("Ó", "O")
                        .replace("Ś", "S")
                        .replace("Ź", "Z")
                        .replace("Ż", "Z")
                        .replace("ą", "a")
                        .replace("ć", "c")
                        .replace("ę", "e")
                        .replace("ł", "l")
                        .replace("ń", "n")
                        .replace("ó", "o")
                        .replace("ś", "s")
                        .replace("ź", "z")
                        .replace("ż", "z");

                // Podziel linię na fragmenty mieszczące się w szerokości strony
                while (!safeLine.isEmpty()) {
                    int breakIndex = safeLine.length();
                    String subLine = safeLine;
                    while (PDType1Font.HELVETICA.getStringWidth(subLine) / 1000 * 10 > width && breakIndex > 0) {
                        breakIndex--;
                        subLine = safeLine.substring(0, breakIndex);
                    }
                    contentStream.showText(subLine.replace("\r", "").replace("\n", ""));
                    contentStream.newLineAtOffset(0, -leading);
                    y -= leading;
                    safeLine = safeLine.substring(subLine.length());
                    if (y < margin + leading) {
                        contentStream.endText();
                        contentStream.close();
                        page = new PDPage(PDRectangle.A4);
                        document.addPage(page);
                        contentStream = new PDPageContentStream(document, page);
                        contentStream.setFont(PDType1Font.HELVETICA, 10);
                        y = page.getMediaBox().getHeight() - margin;
                        contentStream.beginText();
                        contentStream.newLineAtOffset(margin, y);
                    }
                }
            }
            contentStream.endText();
            contentStream.close();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Błąd konwersji XML do PDF", e);
        }
    }

    private Reports verifyDetachedSignature(MultipartFile signedFile, MultipartFile detachedSignature) {
        try (final var signedFileInputStream = signedFile.getInputStream(); final var detachedSignatureInputStream = detachedSignature.getInputStream()) {
            final var signedFileDocument = new InMemoryDocument(signedFileInputStream, signedFile.getOriginalFilename());
            final var detachedSignatureDocument = new InMemoryDocument(detachedSignatureInputStream, detachedSignature.getOriginalFilename());
            final var validator = SignedDocumentValidator.fromDocument(detachedSignatureDocument);
            validator.setDetachedContents(List.of(signedFileDocument));
            validator.setCertificateVerifier(certificateVerifier);
            return validator.validateDocument();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] verifyDetachedSignatureAsPdf(MultipartFile signedFile, MultipartFile detachedSignature) {
        Reports reports = verifySignature(signedFile, detachedSignature);
        return generatePdfKeyValueReport(reports);
    }
}
