# Operation Shadow Signal: Threat Intelligence & Detection Lab

## Overview
This document details our team's submission for **Operation Shadow Signal (Module 7: Threat Intelligence and Detection)**. Acting as the Security Operations Centre (SOC) team for a fictional fintech (*BlueShield Finance*), we evaluated threat intelligence bulletins, conducted a focused threat hunt, designed and tested detection rules, and drafted an incident response report based on synthetic authentication logs.

## Team Members & Roles
* **Ekogiawe Daniel** – SOC Manager
* **Itohan Mercy Osadolor** – Threat Hunter
* **Igbinoba Theophilus** – Threat Intelligence Analyst
* **Donyegha Gift Preye** – Detection Engineer
* **Omokaro Aisosa Jerry** – Evidence & Reporting Analyst
* **Sahid Clement** – Evidence and Reporting Analyst

---

## Key Exercises & Deliverables

### 1. Threat Intelligence Assessment
* **Bulletin ID:** TI-052
* **Source Reliability:** Medium (Provided by members of a shared sector group without raw log evidence).
* **Analyst Confidence:** High regarding the specific mechanics, while carefully separating observed facts from unverified claims and hypotheses.
* **Identified Gaps:** Lacked login geolocation data, user privilege levels, and specific target mail-forwarding destination details.

### 2. Focused Threat Hunt
* **Hunt Question:** *Was Ruth involved in the login, creation of new MFA, and the implementation of a new mail-forwarding rule?*
* **Timeline Analysis:** Evaluated events ranging from a clean login via a saved-device token at `02:14` to an external mail rule creation at `02:22`, contrasted against an office network login later that morning at `08:30`.
* **MITRE ATT&CK Mapping:** Analyzed procedures involving valid credential sign-ins, MFA modifications, and external mail-forwarding rules.

### 3. Detection Engineering & Testing
* **Rule Logic:** Trigger an alert if an account logs 5 or more failed login attempts within any 10-minute window.
* **Testing Outcomes:** Evaluated against positive cases (P1, P2) and negative cases (N1, N2, N3), noting false-positive vectors (e.g., accidental caps lock) and false-negative vulnerabilities (e.g., credential stuffing under the threshold or valid credential abuse).

### 4. Incident Response & Recommendations
* Handled live injects indicating unauthorized activity while credentials remained valid (pointing towards session token reuse or compromised saved-device tokens).
* Recommended immediate asset isolation, credential resets, and external domain traffic investigations.
