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
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
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

    private static final float PDF_MARGIN = 5f;
    private static final float PDF_FONT_SIZE = 10f;
    private static final float PDF_LEADING = 12f;

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

        TrustedListsCertificateSource tslSource = new TrustedListsCertificateSource();

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
        dataLoader.setCacheExpirationTime(24 * 60 * 60 * 1000L);

        tlValidationJob.setOnlineDataLoader(dataLoader);
        tlValidationJob.setSynchronizationStrategy(new ExpirationAndSignatureCheckStrategy());

        TLSource plTslSource = new TLSource();
        plTslSource.setUrl("https://www.nccert.pl/tsl/PL_TSL.xml");
        plTslSource.setCertificateSource(tslSigningCertSource);

        tlValidationJob.setTrustedListSources(plTslSource);
        tlValidationJob.onlineRefresh();
        System.out.println("TSL OK: " + tslSource.getNumberOfTrustedEntityKeys() + " cert\u00F3w");

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
        }
        return verifyDetachedSignature(signedFile, detachedSignature);
    }

    private Reports verifySignature(MultipartFile signedFile) {
        try (var is = signedFile.getInputStream()) {
            var doc = new InMemoryDocument(is, signedFile.getOriginalFilename());
            var validator = SignedDocumentValidator.fromDocument(doc);
            validator.setCertificateVerifier(certificateVerifier);
            return validator.validateDocument();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] xmlToPdf(String xml) {
        return generatePdfFromLines(List.of(xml.split("\n")));
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
            float cellHeight = 20f;
            float[] colWidths = {80, 80, 100, 100, 100};
            float x;

            contentStream.beginText();
            contentStream.newLineAtOffset(margin, y);
            contentStream.showText("Raport weryfikacji podpis\u00F3w elektronicznych");
            contentStream.endText();

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
                    String cell = sanitizeTableCell(row[i], 40);
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
            throw new RuntimeException("B\u0142\u0105d generowania PDF z tabel\u0105", e);
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

            contentStream.beginText();
            contentStream.newLineAtOffset(margin, y);
            contentStream.showText("Raport weryfikacji podpis\u00F3w elektronicznych");
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
                    String value = sanitizeTableCell(pair[1], 80);
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
                y -= leading / 2;
            }
            contentStream.close();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("B\u0142\u0105d generowania PDF (klucz-warto\u015B\u0107)", e);
        }
    }

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

        if (obj instanceof Collection<?>) {
            int idx = 0;
            for (Object item : (Collection<?>) obj) {
                buildKeyValueTree(item, keyPrefix + "[" + idx + "]: ", level + 1, maxLevel, lines, visited);
                idx++;
            }
            return;
        }

        if (obj instanceof Map<?, ?>) {
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) obj).entrySet()) {
                buildKeyValueTree(entry.getValue(), keyPrefix + entry.getKey() + ": ", level + 1, maxLevel, lines, visited);
            }
            return;
        }

        Method[] methods = clazz.getMethods();
        for (Method m : methods) {
            if (isSimpleGetter(m)) {
                String fieldName = toFieldName(m.getName());
                try {
                    Object value = m.invoke(obj);
                    String indent = "  ".repeat(level);
                    if (isSimpleValue(value)) {
                        lines.add(indent + fieldName + ": " + value);
                    } else {
                        lines.add(indent + fieldName + ":");
                        buildKeyValueTree(value, indent + "  ", level + 1, maxLevel, lines, visited);
                    }
                } catch (Exception ignored) {
                    // intentionally ignored: some getters may throw during reflection traversal
                }
            }
        }
    }

    public byte[] generatePdfKeyValueTreeReport(Reports reports) {
        List<String> lines = new ArrayList<>();
        Object simpleReport = reports.getSimpleReport();
        buildKeyValueTree(simpleReport, "", 0, 3, lines, new HashSet<>());
        return generatePdfFromLines(lines);
    }

    private byte[] generatePdfFromLines(List<String> lines) {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            PDPageContentStream contentStream = new PDPageContentStream(document, page);
            contentStream.setFont(PDType1Font.HELVETICA, PDF_FONT_SIZE);

            float width = page.getMediaBox().getWidth() - 2 * PDF_MARGIN;
            float y = page.getMediaBox().getHeight() - PDF_MARGIN;
            contentStream.beginText();
            contentStream.newLineAtOffset(PDF_MARGIN, y);

            for (String line : lines) {
                String safeLine = sanitizePdfText(line);
                while (!safeLine.isEmpty()) {
                    String subLine = fitLineToWidth(safeLine, width);
                    contentStream.showText(removeLineBreaks(subLine));
                    contentStream.newLineAtOffset(0, -PDF_LEADING);
                    y -= PDF_LEADING;
                    safeLine = safeLine.substring(subLine.length());

                    if (y < PDF_MARGIN + PDF_LEADING) {
                        contentStream.endText();
                        contentStream.close();
                        page = new PDPage(PDRectangle.A4);
                        document.addPage(page);
                        contentStream = new PDPageContentStream(document, page);
                        contentStream.setFont(PDType1Font.HELVETICA, PDF_FONT_SIZE);
                        y = page.getMediaBox().getHeight() - PDF_MARGIN;
                        contentStream.beginText();
                        contentStream.newLineAtOffset(PDF_MARGIN, y);
                    }
                }
            }

            contentStream.endText();
            contentStream.close();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("B\u0142\u0105d konwersji XML do PDF", e);
        }
    }

    private String sanitizePdfText(String line) {
        return line.replace("\t", " ")
                .replace("\u000B", " ")
                .replace("\u000C", " ")
                .replace("\u0085", " ")
                .replace("\u2028", " ")
                .replace("\u2029", " ")
                .replace("\u0104", "A")
                .replace("\u0106", "C")
                .replace("\u0118", "E")
                .replace("\u0141", "L")
                .replace("\u0143", "N")
                .replace("\u00D3", "O")
                .replace("\u015A", "S")
                .replace("\u0179", "Z")
                .replace("\u017B", "Z")
                .replace("\u0105", "a")
                .replace("\u0107", "c")
                .replace("\u0119", "e")
                .replace("\u0142", "l")
                .replace("\u0144", "n")
                .replace("\u00F3", "o")
                .replace("\u015B", "s")
                .replace("\u017A", "z")
                .replace("\u017C", "z");
    }

    private String fitLineToWidth(String line, float width) throws IOException {
        int breakIndex = line.length();
        String subLine = line;
        while (PDType1Font.HELVETICA.getStringWidth(subLine) / 1000 * PDF_FONT_SIZE > width && breakIndex > 0) {
            breakIndex--;
            subLine = line.substring(0, breakIndex);
        }
        return subLine;
    }

    private String removeLineBreaks(String text) {
        return text.replace("\r", "").replace("\n", "");
    }

    private String sanitizeTableCell(String value, int maxLength) {
        String cell = value != null ? value.replaceAll("[\r\n\t]", " ") : "";
        if (cell.length() > maxLength) {
            return cell.substring(0, maxLength - 3) + "...";
        }
        return cell;
    }

    private boolean isSimpleGetter(Method method) {
        return method.getParameterCount() == 0
                && Modifier.isPublic(method.getModifiers())
                && (method.getName().startsWith("get") || method.getName().startsWith("is"))
                && !"getClass".equals(method.getName());
    }

    private boolean isSimpleValue(Object value) {
        return value == null
                || value instanceof String
                || value instanceof Number
                || value instanceof Boolean
                || value instanceof Enum;
    }

    private String toFieldName(String methodName) {
        String fieldName = methodName.replaceFirst("^(get|is)", "");
        if (fieldName.isEmpty()) {
            return fieldName;
        }
        return Character.toLowerCase(fieldName.charAt(0)) + fieldName.substring(1);
    }

    private Reports verifyDetachedSignature(MultipartFile signedFile, MultipartFile detachedSignature) {
        try (var signedFileInputStream = signedFile.getInputStream();
             var detachedSignatureInputStream = detachedSignature.getInputStream()) {
            var signedFileDocument = new InMemoryDocument(signedFileInputStream, signedFile.getOriginalFilename());
            var detachedSignatureDocument = new InMemoryDocument(detachedSignatureInputStream, detachedSignature.getOriginalFilename());
            var validator = SignedDocumentValidator.fromDocument(detachedSignatureDocument);
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


