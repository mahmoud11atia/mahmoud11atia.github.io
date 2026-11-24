---
title: "Azure Cloud SOC Lab — Part 3: Brute-Force Correlation, Entity Mapping & AI-Powered SOAR Playbooks"
date: 2026-11-24 03:00:00 +0200
categories: [Sentinel Lab, Microsoft Sentinel]
tags: [azure, microsoft-sentinel, kql, windows-security, mitre-attack, sc-200, soar, logic-apps, detection-engineering, ai-soc]
image:
  path: /assets/img/posts/soc-lab-part3/cover.png
  alt: Azure Cloud SOC Lab Part 3
---

## Overview

In this part of the **Azure Cloud SOC Lab**, I moved from single-event alerts to **correlation detection** and **automated response** in Microsoft Sentinel. I built a **Scheduled Analytics Rule** (`Brute Force Followed by Successful Logon (4625 -> 4624)`) that detects repeated failed logons followed by a successful logon from the same source IP against `vm-win-target`, mapped its output fields to **Sentinel entities** (IP, Account, Host), and built two Logic App playbooks: `pb-incident-notify` to email the SOC on every new incident, and `enrich-with-MITTRE-via-LLM` to automatically enrich incidents with **Google Gemini** MITRE ATT&CK analysis and remediation guidance.

## 1. Building the Brute-Force-to-Success Correlation Rule

In Part 2, the rule `Repeated Failed Windows Logons (Brute Force Signal)` told us someone was *guessing* passwords. The question an analyst really needs answered next is: **did the guessing work?** A successful logon (`EventID 4624`) from the same IP *after* repeated failures (`EventID 4625`) is a much stronger indicator of compromise, so I built a second **Scheduled query rule** to catch exactly that pattern.

In **Microsoft Sentinel**, I went to **Analytics** → **+ Create** → **Scheduled query rule** and configured the rule:

* **Name:** `Brute Force Followed by Successful Logon (4625 -> 4624)`
* **Severity (`High`):** A failed-then-successful pattern means an attacker may already have valid credentials, so this deserves higher priority than the Part 2 rule (`Medium`).
* **Run query every:** `5 Minutes`
* **Lookup data from the last:** `15 Minutes`

### MITRE ATT&CK Alignment

* **Tactic — Initial Access (`TA0001`):** A successful remote logon after repeated failures suggests the adversary got into `vm-win-target` using a valid account.
* **Tactic — Credential Access (`TA0006`):** The failed attempts before the success show the credential guessing that made it possible.
* **Techniques:** The behavior lines up with **Brute Force (`T1110`)** followed by the use of **Valid Accounts (`T1078`)** over RDP.

### Rule Query & Logic

This query is a step up from Part 2 because it uses **two sub-queries** (`let` statements) and a **join** to combine them. Think of it as two assembly lines, one collecting the failures and one collecting the successes, that meet at a single checkpoint: the source IP.

~~~kusto
let FailedLogons = SecurityEvent
| where Computer has "vm-win-target"
| where EventID == 4625
| where isnotempty(IpAddress) and IpAddress != "-"
| summarize FailedAttempts = count(),
            FirstFailedTime = min(TimeGenerated),
            LastFailedTime = max(TimeGenerated)
  by IpAddress
| where FailedAttempts >= 3;
let SuccessfulLogons = SecurityEvent
| where Computer has "vm-win-target"
| where EventID == 4624
| where LogonType in (10, 3)
| where isnotempty(IpAddress) and IpAddress != "-"
| project SuccessTime = TimeGenerated,
          IpAddress,
          CompromisedAccount = Account,
          TargetHost = Computer,
          LogonType;
FailedLogons
| join kind=inner (SuccessfulLogons) on IpAddress
| where SuccessTime > LastFailedTime
| summarize FailedAttempts = max(FailedAttempts),
            FirstFailedTime = min(FirstFailedTime),
            LastFailedTime = max(LastFailedTime),
            SuccessEvents = count(),
            FirstSuccessTime = min(SuccessTime),
            LastSuccessTime = max(SuccessTime)
  by IpAddress, CompromisedAccount, TargetHost
| extend AccountName = CompromisedAccount, HostName = TargetHost
~~~

#### Step-by-Step Breakdown for KQL Beginners

1. **`let FailedLogons = ...`** — Creates a reusable, named result set. It filters `SecurityEvent` to failed logons (`EventID 4625`) on `vm-win-target`, removes blank or `"-"` IP addresses, then groups by `IpAddress` to count `FailedAttempts` and capture `FirstFailedTime` and `LastFailedTime`. The final `where FailedAttempts >= 3` keeps only IPs with 3 or more failures.
2. **`let SuccessfulLogons = ...`** — Creates a second result set for successful logons (`EventID 4624`). The filter `LogonType in (10, 3)` keeps only **Remote Interactive / RDP (10)** and **Network (3)** logons. `project` then renames the fields we need: `SuccessTime`, `CompromisedAccount` and `TargetHost`.
3. **`FailedLogons | join kind=inner (SuccessfulLogons) on IpAddress`** — Connects the two result sets. An `inner` join keeps only IPs that appear in **both**, meaning IPs that failed repeatedly *and* also logged on successfully.
4. **`| where SuccessTime > LastFailedTime`** — Enforces the order of events. The success must happen **after** the last failure, which filters out earlier, legitimate sessions from the same IP.
5. **`| summarize ... by IpAddress, CompromisedAccount, TargetHost`** — Collapses the matches into one row per IP, account and host, with the failure count, success count and time windows for the analyst.
6. **`| extend AccountName = CompromisedAccount, HostName = TargetHost`** — Creates columns named exactly `AccountName` and `HostName`, so they can be mapped as **Account** and **Host** entities in the next step.

After the query, I went through **Incident settings** and **Automated response**, then **Review + create**. The wizard showed **Validation passed**, with `High` severity, `Enabled` status, a 5-minute frequency and a 15-minute lookback.

![Review and Create Page for the New Scheduled Rule](/assets/img/posts/soc-lab-part3/create-new-rule.png){: .normal }

## 2. Configuring Entity Mapping

At the end of Part 2, the incident showed `No entities` and `Assets: 0`, because the rule had no entity mapping. **Entity mapping** tells Microsoft Sentinel which query fields are IPs, accounts and hosts, so alerts and incidents link them together and the attack graph can be built.

Inside **Set rule logic**, I expanded **Alert enhancement** → **Entity mapping** and added three entities:

| Entity | Identifier | Field |
|---------|------------|---------------|
| IP | Address | `IpAddress` |
| Account | FullName | `AccountName` |
| Host | HostName | `HostName` |

![Entity Mapping in the Analytics Rule Wizard](/assets/img/posts/soc-lab-part3/entity.png){: .normal }

> **Key point:** Entity mapping only works if the mapped field names **exactly match** the query output. That is why the query ends with the `extend` line that creates `AccountName` and `HostName`. Without it, the mappings would point to fields that do not exist and the entities would come up empty.
{: .prompt-tip }

With both rules saved, the **Analytics** table now shows the new `High` severity correlation rule alongside the earlier `Medium` brute-force signal rule, both `Enabled`.

![Both Scheduled Analytics Rules Enabled in Sentinel](/assets/img/posts/soc-lab-part3/new-rule.png){: .normal }

## 3. Building the `pb-incident-notify` Playbook & Automation Rule

Detection alone is not enough, because someone has to see the incident. I automated notification with an **Azure Logic App playbook** (`pb-incident-notify`) in resource group `RG-sentinel-lab`.

### Designing the Playbook

1. Created a playbook with a **Microsoft Sentinel incident** trigger.
2. In the Logic App designer, added a **Send an email (V2)** action below the trigger.
3. Filled the email subject and body with dynamic incident fields (**Incident Title**, **Severity**, **Status**, **Description** and **Incident URL**) along with the workspace details (`law-sentinel-lab`, `RG-sentinel-lab`).
4. Saved the playbook.

![Logic App Designer with Sentinel Incident Trigger and Send an Email Action](/assets/img/posts/soc-lab-part3/simple-playbook.png){: .normal }

> **Troubleshooting:** Pairing the `azuresentinel` connector with the shared Gmail connector triggered a `GmailConnectorPolicyViolation` error during validation. Switching to the **Send an email (V2)** action passed workflow validation cleanly.
{: .prompt-warning }

### Connecting the Playbook with an Automation Rule

A playbook does nothing until something triggers it, so I attached it to the rule through an **automation rule**:

1. Opened the analytics rule → **Automated response** → **+ Add new**.
2. When `pb-incident-notify` showed **No Microsoft Sentinel permissions**, I clicked **Manage playbook permissions** and granted Sentinel permission to run it.
3. Configured the automation rule:
   * **Trigger:** `When incident is created`
   * **Conditions:** `Analytic rule name` `Contains` `Current rule`
   * **Actions:** `Run playbook` → `pb-incident-notify`
   * **Order:** `1`
4. Clicked **Apply**, then completed **Review + create** and saved the rule.

![Automation Rule Running the pb-incident-notify Playbook](/assets/img/posts/soc-lab-part3/connect-with-playbook.png){: .normal }

## 4. Validating the Attack Simulation (`Incident ID 25`)

With the VM running, I repeated the attack simulation from Kali Linux (`156.207.200.227`): several failed RDP logons against `vm-win-target`, followed by a successful logon. Sentinel triggered the new rule and generated **Case `ID 25: Brute Force Followed by Successful Logon`** with **High** severity and **New** status.

![Generated Incident ID 25 and Attack Graph in Microsoft Sentinel](/assets/img/posts/soc-lab-part3/bruteforce-incident.png){: .normal }

> The incident title shows `4625 -_ 4624` instead of `4625 -> 4624`. Sentinel replaced the `>` character in the rule name. Renaming the rule to something like `4625 to 4624` avoids this.
{: .prompt-info }

Right after the incident was created, the automation rule ran `pb-incident-notify` and the alert email arrived with the incident title, severity, status, workspace, resource group and a direct link to the incident in Sentinel.

![Email Alert Sent by the pb-incident-notify Playbook](/assets/img/posts/soc-lab-part3/email-notify.png){: .normal }

## 5. AI-Powered Incident Enrichment with Google Gemini (`enrich-with-MITTRE-via-LLM`)

Sending an email alert (`pb-incident-notify`) solves notification, but the analyst still has to manually map the behavior to **MITRE ATT&CK** and document initial triage steps. To accelerate Tier-1/Tier-2 investigation, I built a second SOAR playbook named `enrich-with-MITTRE-via-LLM` inside `RG-sentinel-lab` that sends incident context to **Google Gemini** and posts a structured threat analysis directly into the incident comments.

### Step 1: Designing the Logic App Workflow

1. Created a new Logic App playbook triggered by **Microsoft Sentinel incident**.
2. Added the **Google Gemini (Independent Publisher)** → **Generate text content** action and authenticated it with a Google AI Studio API key.
3. Configured the model parameters:
   - **API Version:** `v1beta`
   - **Model Name:** `gemini-2.5-flash`
   - **Contents (`Role - 1`):** `user`
   - **Prompt (`Parts Items Text - 1`):** Passed dynamic incident fields (**Incident Title**, **Incident Description**, and **Incident Severity**) instructing Gemini to act as a Senior SOC Analyst and return MITRE ATT&CK Tactics/Techniques, mapping justification, and containment steps.
4. Added **Microsoft Sentinel** → **Add comment to incident (V3)** below the Gemini step, mapping `Incident ARM ID` from the trigger and the generated `text` output from Gemini (which automatically wraps the action inside a `For each` loop to parse the response array).

![Logic App Workflow for MITRE ATT&CK Enrichment](/assets/img/posts/soc-lab-part3/playbook.png){: .normal }

> **Tip:** Avoid legacy model names like `gemini-pro` in the connector configuration, as deprecated endpoints will fail at runtime. Using current models such as `gemini-2.5-flash` with `Role` explicitly set to `user` ensures reliable JSON responses.
{: .prompt-tip }

### Step 2: Granting Managed Identity Permissions (Fixing `403 Forbidden`)

During the initial test run, the Gemini step succeeded in 11 seconds, but **Add comment to incident (V3)** failed with a `Forbidden` error. Because the playbook authenticates to Sentinel using its **System-assigned Managed Identity**, it needs explicit RBAC permissions to write back to incidents:

1. Opened the playbook's **Identity** blade in Azure and verified **System assigned** status was set to **On**.
2. Navigated to the resource group `RG-sentinel-lab` → **Access control (IAM)** → **+ Add** → **Add role assignment**.
3. Selected the **Microsoft Sentinel Responder** role, chose **Managed identity**, and assigned it to `enrich-with-MITTRE-via-LLM`.

![Assigning Microsoft Sentinel Responder Role to the Playbook Managed Identity](/assets/img/posts/soc-lab-part3/give-permission.png){: .normal }

> **Troubleshooting:** If **Add comment to incident (V3)** throws a `403 Forbidden` error even when your user account is an Owner, check the Logic App's **System-assigned Managed Identity** and grant it **Microsoft Sentinel Responder** on the Sentinel resource group.
{: .prompt-warning }

### Step 3: Validating AI Triage on a Live Incident (`Incident ID 29`)

To validate the enrichment workflow end to end, I ran another brute-force-to-success simulation, generating **Case `ID 29: Brute Force Followed by Successful Logon (4625 -_ 4624)`**. From the incident's **Actions → Run playbook** blade, both `pb-incident-notify` and `enrich-with-MITTRE-via-LLM` were active and ready to execute.

![Running the AI Enrichment Playbook on the Sentinel Incident](/assets/img/posts/soc-lab-part3/total-playbook.png){: .normal }

Within seconds of triggering `enrich-with-MITTRE-via-LLM`, a formatted triage report appeared under **Comments & Attachments** authored by `Playbook-enrich-with-MITTRE-via-LLM`. Gemini accurately identified the `4625 -> 4624` sequence as a confirmed account compromise pattern:

![Automated Gemini Triage Summary Inside Incident ID 29](/assets/img/posts/soc-lab-part3/comment1.png){: .normal }

Scrolling further down the comment shows the granular **MITRE ATT&CK** breakdown—mapping **Credential Access (`T1110` — Brute Force / `T1110.001` — Password Guessing)**, **Initial Access (`T1078` — Valid Accounts)**, and **Persistence (`T1078`)**—followed by justification and actionable containment steps:

![Detailed MITRE ATT&CK Tactics and Sub-Techniques Generated by Gemini](/assets/img/posts/soc-lab-part3/comment2.png){: .normal }

### Final Lab Architecture Summary

By combining correlation rules, entity mapping, and dual SOAR playbooks, the SOC workflow in `law-sentinel-lab` now operates as a complete closed-loop pipeline:

1. **Detection & Correlation:** KQL joins `4625` failures with `4624` successes on the same source IP (`High` severity).
2. **Context & Graph:** Entity mapping links IP, Account, and Host into a visual attack graph.
3. **Notification (`pb-incident-notify`):** Immediately alerts the SOC team via email with direct triage links.
4. **AI Enrichment (`enrich-with-MITTRE-via-LLM`):** Automatically maps the incident to MITRE ATT&CK tactics/techniques and writes remediation guidance straight into the case comments.


### Triage Takeaways

1. **Entity Mapping Worked:** Compared with Incident 19 in Part 2 (`No entities`, `Assets: 0`), Incident 25 shows `3` assets and an attack graph linking the source IP `156.207.200.227` to the target host `vm-win-target` and the account `m7moud3ttia`.
2. **Timeline Verification:** The incident shows `1/1` active alert, `1` evidence item and `2` activities, with first activity at `Nov 24, 2026 2:16:47 AM` and last activity at `2:31:47 AM`.
3. **Automation Verified End to End:** The chain of correlation rule → incident → automation rule → playbook → email worked without any manual step. The email arrived with the same details an analyst needs to start triage.
4. **Next Analyst Step:** Because a successful logon followed the failures, a real analyst would now treat the account as potentially compromised, reviewing what that session did and resetting the credentials.

topic here]*.
