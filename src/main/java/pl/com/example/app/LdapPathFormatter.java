package pl.com.example.app;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class LdapPathFormatter {

    private static final Map<String, String> LDAP_LABELS = new LinkedHashMap<>();
    private static final List<String> LDAP_ATTRIBUTE_ORDER;

    static {
        LDAP_LABELS.put("CN", "Nazwa zwyczajowa");
        LDAP_LABELS.put("OU", "Jednostka organizacyjna");
        LDAP_LABELS.put("O", "Organizacja");
        LDAP_LABELS.put("C", "Kraj");
        LDAP_LABELS.put("L", "Miejscowość");
        LDAP_LABELS.put("ST", "Stan / województwo");
        LDAP_LABELS.put("DC", "Składnik domeny");
        LDAP_LABELS.put("UID", "Identyfikator użytkownika");
        LDAP_LABELS.put("SN", "Nazwisko");
        LDAP_LABELS.put("GN", "Imię");
        LDAP_LABELS.put("E", "E-mail");
        LDAP_LABELS.put("EMAILADDRESS", "Adres e-mail");

        LDAP_ATTRIBUTE_ORDER = List.copyOf(LDAP_LABELS.keySet());
    }

    public static String toHumanReadableLdapPath(String ldapPath) {
        if (ldapPath == null || ldapPath.isBlank()) {
            return "";
        }

        try {
            final var ldapName = new LdapName(ldapPath);
            final var result = new StringBuilder();
            final var sortedRdns = ldapName.getRdns().stream()
                    .sorted(Comparator.comparingInt(rdn -> sortOrder(rdn.getType())))
                    .toList();

            for (final var rdn : sortedRdns) {
                final var key = rdn.getType().toUpperCase(Locale.ROOT);
                final var label = LDAP_LABELS.getOrDefault(key, key);

                if (!result.isEmpty()) {
                    result.append(System.lineSeparator());
                }

                result.append(label)
                        .append(": ")
                        .append(rdn.getValue());
            }

            return result.toString();
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException("Invalid LDAP path: " + ldapPath, e);
        }
    }

    private static int sortOrder(String attribute) {
        final var index = LDAP_ATTRIBUTE_ORDER.indexOf(attribute.toUpperCase(Locale.ROOT));
        return index >= 0 ? index : Integer.MAX_VALUE;
    }
}
