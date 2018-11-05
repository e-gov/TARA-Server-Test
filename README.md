# TARA integratsioonitestid

**NB! Antud testid on arenduses ning  muutuvad projekti edenedes.**

## Testide seadistamine ja käivitamine

**NB!** Vajalik on Java VM ja Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy eelnev installatsioon. Arenduseks on kasutatud Oracle Java jdk 1.8.0_162 versiooni.

**NB!** Vajalik on juurdepääs TARA teenusele, selleks peab kas liituma RIA TARA testteenusega või paigaldama lokaalse TARA teenuse.

1. Hangi TARA testid:

 `git clone https://github.com/e-gov/TARA-Server-Test.git`

2. Seadista testid vastavaks testitava TARA rakenduse otspunktidele. Selleks on kaks võimalust:

a) Võimalik on ette anda kahe erineva "profiili" properties faile "dev" ja "test" - vastavad properties failid [application-dev.properties](https://github.com/e-gov/TARA-Server-Test/blob/master/src/test/resources/application-dev.properties) ja [application-test.properties](https://github.com/e-gov/TARA-Server-Test/blob/master/src/test/resources/application-test.properties). Vaikeväärtusena on kasutusel profiil "dev", kuid seda on võimalik käivitamisel muuta parameetriga. Testide vaikeväärtused on seadistatud [application.properties](https://github.com/e-gov/TARA-Server-Test/blob/master/src/test/resources/application.properties) failis.

b) Andes vastavad parameetrid ette testide käivitamisel (kirjeldus testide käivitamise punktis)

TARA OpenID Connect spetsiifilised väärtused - vajalikud suhtlemiseks TARA-ga.

| Parameeter | Vaikeväärtus | Kirjeldus |
|------------|--------------|-----------|
| test.tara.testRedirectUri | https://localhost:8451/oauth/response | TARA OpenID Connect teenuses registreeritud return URI. |
| test.tara.clientId | registeredClientId | TARA OpenID Connect teenuses registreeritud kliendi id. |
| test.tara.clientSecret | sharedSecret | TARA OpenID Connect teenuses registreeritud salajane "võti". |
| test.tara.targetUrl | https://localhost:443 | TARA teenuse URL. |
| test.tara.jwksUrl | /oidc/jwks | TARA OpenID Connect avaliku võtme otspunkt. |
| test.tara.authorizeUrl | /oidc/authorize | TARA autentimise alustamise otspunkt. |
| test.tara.tokenUrl | /oidc/token | TARA tokeni otspunkt. |
| test.tara.loginUrl | /login | TARA sisse logimise otspunkt. |
| test.tara.configurationUrl | /oidc/.well-known/openid-configuration | TARA konfiguratsiooni otspunkt. |
| test.tara.backendUrl | http://localhost:8081 | TARA Tomcati-i URL, vajalik ID-Kaardi sertifikaadi saatmiseks. |
| test.tara.domainNamelocalhost | localhost | TARA teenuse domeeni nimi, vajalik küpsise salvestamisel. |
| test.tara.banklinkMockUrl | http://localhost:8990/ipizza | Pangalingi mock teenuse URL |
| test.tara.manageUrl | https://localhost:8443 | TARA-Management teenuse URL |

TARA HTTPS sertifikaadid - vajalikud kui test.tara.backendUrl algab https-iga

| Parameeter | Vaikeväärtus | Kirjeldus |
|------------|--------------|-----------|
| test.tara.frontEndKeystore | src/test/resources/tara-fe.p12 | TARA front-end serveri HTTPS kliendisertifikaadi ja võtme asukoht. |
| test.tara.frontEndKeystorePassword | secret | Võtmehoidla parool. |
| test.tara.backEndTruststore | src/test/resources/tara-be.p12 | TARA back-end serveri HTTPS sertifikaat. |
| test.tara.backEndTruststorePassword | secret | Usalduslao parool. |

eIDAS node spetsiifilised väärtused - vajalikud simuleerimaks eIDAS nodei.

| Parameeter | Vaikeväärtus | Kirjeldus |
|------------|--------------|-----------|
| test.tara.eidasNodeUrl | http://localhost:8080 | TARA-ga ühendatud eIDAS nodei aadress. |
| test.tara.eidasNodeConnectorMetadataUrl | /EidasNode/ConnectorMetadata | Konnektorteenuse metadata url. |
| test.tara.eidasNodeServiceMetadataUrl | /EidasNode/ServiceMetadata | Proksiteenuse metadata url |
| test.tara.eidasNodeResponseUrl | /EidasNode/ColleagueResponse | eIDAS node-i tagasipöördumise url |

Võtmete seadistamise väärtused - vajalikud sõnumite allkirjastamiseks

| Parameeter | Vaikeväärtus | Kirjeldus |
|------------|--------------|-----------|
| test.tara.keystore | classpath:samlKeystore.jks | Võtmehoidla |
| test.tara.keystorePass | changeit | Võtmehoidla parool |
| test.tara.responseSigningKeyId | aare_meta | Allkirjastamise võtme id |
| test.tara.responseSigningKeyPass | changeit | Allkirjastamise võtme parool |

4. Käivita testid:

`./mvnw clean install`

Testidele parameetrite ette andmine käivitamisel:

`./mvnw clean install -Dtest.tara.targetUrl=http://localhost:1881`

a) IntelliJ-s käivitamiseks on vajalik [Lombok plugin](https://plugins.jetbrains.com/plugin/6317-lombok-plugin)

b) IntelliJ-s üksiku testi Allure raporti genereerimiseks on vaja test käivitada läbi Maveni. Selle jaoks on hetkel vajalik [Maven Helper](https://plugins.jetbrains.com/plugin/7179-maven-helper) plugin.

5. Kontrolli testide tulemusi

a) Testid väljastavad raporti ja logi jooksvalt käivituskonsoolis

b) Surefire pistikprogramm väljastab tulemuste raporti ../target/surefire-reports kausta. Võimalik on genereerida ka html kujul koondraport. Selleks käivitada peale testide käivitamist käsk:

`./mvnw surefire-report:report-only`

Html raport on leitav ../target/site/ kaustast.
c) [Allure](https://github.com/allure-framework/allure2) raporti vaatamiseks on käsk `./mvnw allure:serve` ja raporti arhiveerimiseks `./mvnw allure:report`


6. Testide arendamine
Kasutada Hamcresti kontrolle - `assertThat(actual, equalTo(expected))`. JUnit-i assertidel on argumentide järjekord teistpidine ja tekitab segadust `assertEquals(expected, actual)`
Kõik rakenduse olekut mõjutavad tegevused peaks olema Allure raportis - HTTP päringud, andmebaasi muudatused, jms
