# STRIDE Threat Model — Vulnerability Tracker

This document outlines the primary security threats, trust boundaries, and implemented mitigations for the Vulnerability Tracker application using the STRIDE methodology.


## STRIDE Analysis & Mitigations

### 1. Spoofing (Faking Identity)
- **Threat:** An attacker impersonates a PM or Analyst to triage findings, reassign developers, or alter SLA targets.
- **Mitigation:** Do not handle passwords in .NET or React. Delegate all authentication to an external Identity Provider (Keycloak) via OIDC.

### 2. Tampering (Modifying Data)
- **Threat:** A compromised developer account secretly changes a "Critical" vulnerability to "Remediated" without fixing it, or tampers with exported reports.
- **Mitigation:** Implement strict role-based access control (RBAC) where Developers cannot close findings independently, and digitally sign exported reports to ensure integrity.

### 3. Repudiation (Denying Actions)
- **Threat:** An Analyst deletes a finding and later claims they never touched it.
- **Mitigation:** Implement a robust, tamper-evident audit trail logging exactly who changed what, and when.

### 4. Information Disclosure (Data Breaches)
- **Threat:** An attacker gains access to the database and reads the sensitive details of unpatched vulnerabilities.
- **Mitigation:** Encrypt the specific finding details (like descriptions and steps to reproduce) at the application level in .NET before saving them to the database.

### 5. Denial of Service (Crashing or Flooding the App)
- **Threat:** Bots spam the unauthenticated public vulnerability reporting form, overwhelming the database.
- **Mitigation:** Implement rate limiting on the .NET API endpoint that handles the public form, and consider a CAPTCHA on the React frontend.

### 6. Elevation of Privilege (Gaining Unintended Power)
- **Threat:** AAn authenticated External Reporter bypasses the frontend UI and sends direct API requests to view all system findings.
- **Mitigation:** Never trust the React frontend. Enforce strictly scoped authorization policies on every single .NET API controller to ensure only Analysts, PMs, and Auditors can read findings.