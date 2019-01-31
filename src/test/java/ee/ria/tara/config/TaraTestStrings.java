package ee.ria.tara.config;

public class TaraTestStrings {
    //SAML response strings
    public static final String LOA_LOW = "http://eidas.europa.eu/LoA/low";
    public static final String LOA_SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";
    public static final String LOA_HIGH = "http://eidas.europa.eu/LoA/high";
    public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    public static final String ISSUER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    public static final String SUBJECT_CONFIRMATION_METHOD_SENDER_VOUCHES = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";
    public static final String SUBJECT_CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public static final String NAME_ID_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    public static final String NAME_ID_FORMAT_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    public static final String NAME_ID_FORMAT_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    public static final String NAME_ID_FORMAT_ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";

    //Test data strings
    public static final String DEFATTR_FIRST = "Test-FirstName";
    public static final String DEFATTR_FAMILY = "Test-FamilyName";
    public static final String DEFATTR_PNO = "EE/CA/30011092212";
    public static final String DEFATTR_DATE = "1900-11-09";
    public static final String DEFATTR_BIRTH_NAME = "Test-Birth-First-Last-Name";
    public static final String DEFATTR_BIRTH_PLACE = "Country";
    public static final String DEFATTR_ADDR = "PGVpZGFzOkxvY2F0b3JEZXNpZ25hdG9yPjIyPC9laWRhczpMb2NhdG9yRGVzaWduYXRvcj4NCjxlaWRhczpUaG9yb3VnaGZhcmU+QXJjYWNpYSBBdmVudWU8L2VpZGFzOlRob3JvdWdoZmFyZT4NCjxlaWRhczpQb3N0TmFtZT5Mb25kb248L2VpZGFzOlBvc3ROYW1lPiANCjxlaWRhczpQb3N0Q29kZT5TVzFBIDFBQTwvZWlkYXM6UG9zdGNvZGU+";
    public static final String DEFATTR_GENDER = "Male";
    public static final String DEFATTR_LEGAL_NAME = "Good Company a/s";
    public static final String DEFATTR_LEGAL_PNO = "EE/CA/292938483902";
    public static final String DEFATTR_LEGAL_ADDRESS = "PGVpZGFzOkxvY2F0b3JEZXNpZ25hdG9yPjEyNTwvZWlkYXM6TG9jYXRvckRlc2lnbmF0b3I+DQo8ZWlkYXM6VGhvcm91Z2hmYXJlPktpbmdzd2F5PC9laWRhczpUaG9yb3VnaGZhcmU+DQo8ZWlkYXM6UG9zdE5hbWU+TG9uZG9uPC9laWRhczpQb3N0TmFtZT4gDQo8ZWlkYXM6UG9zdENvZGU+V0MyQiA2Tkg8L2VpZGFzOlBvc3Rjb2RlPg==";
    public static final String DEFATTR_LEGAL_VATREGISTRATION = "GB 730 7577 27";
    public static final String DEFATTR_LEGAL_TAXREFERENCE = "ABZ1230789";
    public static final String DEFATTR_LEGAL_D201217EUIDENTIFIER = "GB 755 267 1243";
    public static final String DEFATTR_LEGAL_LEI = "ES123567983568437254K";
    public static final String DEFATTR_LEGAL_EORI = "GB123456789000";
    public static final String DEFATTR_LEGAL_SEED = "GB 00000987ABC";
    public static final String DEFATTR_LEGAL_SIC = "3730";

    //eIDAS strings
    public static final String DEF_COUNTRY = "EE";

    //OpenID Connect string
    public static final String OIDC_AMR_MID = "mID";
    public static final String OIDC_AMR_IDC = "idcard";
    public static final String OIDC_AMR_EIDAS = "eIDAS";
    public static final String OIDC_DEF_SCOPE = "openid";
    public static final String OIDC_OPENID_SCOPE = "openid ";
    public static final String OIDC_EIDAS_ONLY_SCOPE = "eidasonly ";
    public static final String OIDC_IDCARD_SCOPE = "idcard ";
    public static final String OIDC_MID_SCOPE = "mid ";
    public static final String OIDC_EIDAS_SCOPE = "eidas ";
    public static final String OIDC_BANKLINK_SCOPE = "banklink ";
    public static final String OIDC_SMARTID_SCOPE = "smartid ";
    public static final String OIDC_EMAIL_SCOPE = "email ";
    public static final String OIDC_ACR_VALUES_LOW = "low";
    public static final String OIDC_ACR_VALUES_SUBSTANTIAL = "substantial";
    public static final String OIDC_ACR_VALUES_HIGH = "high";
}
