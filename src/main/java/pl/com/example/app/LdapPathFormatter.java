package pl.com.example.app;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.util.LinkedHashMap;
import java.util.Map;

public final class LdapPathFormatter {

    private static final Map<String, String> LDAP_LABELS = new LinkedHashMap<>();

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
    }

    private LdapPathFormatter() {
    }

    public static String toHumanReadableLdapPath(String ldapPath) {
        if (ldapPath == null || ldapPath.isBlank()) {
            return "";
        }

        try {
            LdapName ldapName = new LdapName(ldapPath);
            StringBuilder result = new StringBuilder();

            for (Rdn rdn : ldapName.getRdns()) {
                String key = rdn.getType().toUpperCase();
                String label = LDAP_LABELS.getOrDefault(key, key);

                if (!result.isEmpty()) {
                    result.append(System.lineSeparator());
                }

                result.append(label)
                        .append(": ")
                        .append(rdn.getValue());
            }

            return result.toString();
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException("Nieprawidłowa ścieżka LDAP: " + ldapPath, e);
        }
    }
}
