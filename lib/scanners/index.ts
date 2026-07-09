/**
 * Single import that registers every adapter into the global registry.
 * API routes import from here so module-load order is deterministic.
 *
 * Adapters are grouped by mode (web vs source). Built-in scanners come
 * first so they're listed at the top of the UI; CLI-backed scanners follow.
 */

import { registerScanner } from "../engine/registry";

// Web — built-in
import { headersScanner } from "./web/headers";
import { cookiesScanner } from "./web/cookies";
import { tlsScanner } from "./web/tls";
import { crawlerScanner } from "./web/crawler";
import { portsScanner } from "./web/ports";
import { corsScanner } from "./web/cors";
import { jwtScanner } from "./web/jwt-cookie";
import { fingerprintScanner } from "./web/fingerprint";
import { contentDiscoveryScanner } from "./web/content-discovery";
import { activeInjectionScanner } from "./web/active-injection";
import { subdomainEnumScanner } from "./web/subdomain-enum";
import { formFuzzerScanner } from "./web/form-fuzzer";
import { bruteLoginScanner } from "./web/brute-login";
import { verbTamperingScanner } from "./web/verb-tampering";
import { idorScanner } from "./web/idor";
import { paramMinerScanner } from "./web/param-miner";
import {
  sstiScanner, nosqlScanner, xxeScanner, protoPollutionScanner,
  crlfHostScanner, httpSmugglingScanner, massAssignmentScanner,
  raceConditionScanner, sriScanner,
} from "./web/advanced-injection";
import { sqliScanner } from "./web/sqli";
import { cvePackScanner } from "./web/cve-pack";
import {
  wafScanner, sourceMapScanner, hppScanner, cachePoisonScanner,
  emailAuthScanner, cloudMetaScanner, userEnumScanner, deserializationScanner,
} from "./web/coverage-extras";
import {
  jwtCrackScanner, sessionFixationScanner,
  logoutInvalidationScanner, oauthRedirectScanner,
} from "./web/auth-extras";
import {
  ldapInjectionScanner, xpathInjectionScanner,
  ssiInjectionScanner, jsonpScanner,
} from "./web/extra-injection";
import { fileUploadScanner, zipSlipScanner, rangeLeakScanner } from "./web/upload-tests";
import { graphqlFuzzerScanner } from "./web/graphql-fuzzer";
import {
  privescScanner, jwtTamperScanner, replayAttackScanner, apiKeyInUrlScanner,
} from "./web/authz-extras";
import { dnsAuditScanner, hstsPreloadScanner, s3BucketScanner } from "./web/dns-recon";
import {
  cacheDeceptionScanner, backupFilesScanner, stackTraceScanner,
  wsOriginScanner, storedXssScanner, numericBoundsScanner,
} from "./web/discovery-extras";
import { customRulesScanner } from "./web/custom-rules";
import { oobInteractshScanner } from "./web/oob-interactsh";
import { virusTotalScanner, shodanScanner } from "./web/threat-intel";
import { censysScanner, abuseIpDbScanner, greyNoiseScanner } from "./web/threat-intel-extra";
import { domXssScanner } from "./web/dom-xss";
import { spaCrawlerScanner } from "./web/spa-crawler";
import { queryFuzzerScanner } from "./web/query-fuzzer";

// Web — external CLI / API
import { nucleiScanner } from "./web/nuclei";
import { nmapScanner } from "./web/nmap";
import { ffufScanner, zapApiScanner, wapitiScanner, niktoScanner, sqlmapScanner } from "./web/external-cli";
import {
  testsslScanner, subfinderScanner, httpxScanner, katanaScanner,
  naabuScanner, masscanScanner, dastardlyScanner,
} from "./web/external-cli-extra";

// Source — built-in
import { regexSecretsScanner } from "./source/regex-secrets";

// Source — external CLI
import { semgrepScanner } from "./source/semgrep";
import { gitleaksScanner } from "./source/gitleaks";
import { trivyScanner } from "./source/trivy";
import {
  osvScanner, banditScanner, brakemanScanner,
  eslintSecurityScanner, checkovScanner,
} from "./source/external-cli";
import {
  codeqlScanner, trufflehogScanner, detectSecretsScanner,
  snykScanner, dependencyTrackScanner,
} from "./source/external-cli-extra";
import { lockfileLintScanner } from "./source/lockfile-lint";
import {
  dockleScanner, hadolintScanner, kubeBenchScanner,
  kubeHunterScanner, prowlerScanner, mobsfScanner,
} from "./source/container-cloud-mobile";
import { scoutSuiteScanner, scubaGearScanner } from "./source/cloud-extra";

let registered = false;
export function registerAllScanners(): void {
  if (registered) return;

  // Web — built-in
  registerScanner(headersScanner);
  registerScanner(cookiesScanner);
  registerScanner(tlsScanner);
  registerScanner(crawlerScanner);
  registerScanner(portsScanner);
  registerScanner(corsScanner);
  registerScanner(jwtScanner);
  registerScanner(fingerprintScanner);
  registerScanner(contentDiscoveryScanner);
  registerScanner(activeInjectionScanner);
  registerScanner(subdomainEnumScanner);
  registerScanner(formFuzzerScanner);
  registerScanner(bruteLoginScanner);
  registerScanner(verbTamperingScanner);
  registerScanner(idorScanner);
  registerScanner(paramMinerScanner);
  registerScanner(sstiScanner);
  registerScanner(nosqlScanner);
  registerScanner(xxeScanner);
  registerScanner(protoPollutionScanner);
  registerScanner(crlfHostScanner);
  registerScanner(httpSmugglingScanner);
  registerScanner(massAssignmentScanner);
  registerScanner(raceConditionScanner);
  registerScanner(sriScanner);
  registerScanner(sqliScanner);
  registerScanner(cvePackScanner);
  // coverage extras
  registerScanner(wafScanner);
  registerScanner(sourceMapScanner);
  registerScanner(hppScanner);
  registerScanner(cachePoisonScanner);
  registerScanner(emailAuthScanner);
  registerScanner(cloudMetaScanner);
  registerScanner(userEnumScanner);
  registerScanner(deserializationScanner);
  // auth extras
  registerScanner(jwtCrackScanner);
  registerScanner(sessionFixationScanner);
  registerScanner(logoutInvalidationScanner);
  registerScanner(oauthRedirectScanner);
  // niche injection
  registerScanner(ldapInjectionScanner);
  registerScanner(xpathInjectionScanner);
  registerScanner(ssiInjectionScanner);
  registerScanner(jsonpScanner);
  // file/upload
  registerScanner(fileUploadScanner);
  registerScanner(zipSlipScanner);
  registerScanner(rangeLeakScanner);
  // graphql deep
  registerScanner(graphqlFuzzerScanner);
  // authz extras
  registerScanner(privescScanner);
  registerScanner(jwtTamperScanner);
  registerScanner(replayAttackScanner);
  registerScanner(apiKeyInUrlScanner);
  // dns / hosting recon
  registerScanner(dnsAuditScanner);
  registerScanner(hstsPreloadScanner);
  registerScanner(s3BucketScanner);
  // discovery extras
  registerScanner(cacheDeceptionScanner);
  registerScanner(backupFilesScanner);
  registerScanner(stackTraceScanner);
  registerScanner(wsOriginScanner);
  registerScanner(storedXssScanner);
  registerScanner(numericBoundsScanner);
  registerScanner(customRulesScanner);
  registerScanner(oobInteractshScanner);
  // threat intel
  registerScanner(virusTotalScanner);
  registerScanner(shodanScanner);
  registerScanner(censysScanner);
  registerScanner(abuseIpDbScanner);
  registerScanner(greyNoiseScanner);
  // headless browser
  registerScanner(domXssScanner);
  registerScanner(spaCrawlerScanner);
  registerScanner(queryFuzzerScanner);

  // Web — external
  registerScanner(nucleiScanner);
  registerScanner(nmapScanner);
  registerScanner(ffufScanner);
  registerScanner(zapApiScanner);
  registerScanner(wapitiScanner);
  registerScanner(niktoScanner);
  registerScanner(sqlmapScanner);
  registerScanner(testsslScanner);
  registerScanner(subfinderScanner);
  registerScanner(httpxScanner);
  registerScanner(katanaScanner);
  registerScanner(naabuScanner);
  registerScanner(masscanScanner);
  registerScanner(dastardlyScanner);

  // Source — built-in
  registerScanner(regexSecretsScanner);

  // Source — external
  registerScanner(semgrepScanner);
  registerScanner(gitleaksScanner);
  registerScanner(trivyScanner);
  registerScanner(osvScanner);
  registerScanner(banditScanner);
  registerScanner(brakemanScanner);
  registerScanner(eslintSecurityScanner);
  registerScanner(checkovScanner);
  registerScanner(codeqlScanner);
  registerScanner(trufflehogScanner);
  registerScanner(detectSecretsScanner);
  registerScanner(snykScanner);
  registerScanner(dependencyTrackScanner);
  registerScanner(lockfileLintScanner);
  // container / cloud / mobile
  registerScanner(dockleScanner);
  registerScanner(hadolintScanner);
  registerScanner(kubeBenchScanner);
  registerScanner(kubeHunterScanner);
  registerScanner(prowlerScanner);
  registerScanner(mobsfScanner);
  registerScanner(scoutSuiteScanner);
  registerScanner(scubaGearScanner);

  registered = true;
}

registerAllScanners();
