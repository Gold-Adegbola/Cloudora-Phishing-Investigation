# KQL queries

The queries I wrote for the Cloudora phishing investigation (CLD-0002), run in Azure Data Explorer. Each one answers a single question, and they are listed in the order I ran them.

| File | Question it answers | Result |
|---|---|---|
| [`01_message_trace_delivery.kql`](01_message_trace_delivery.kql) | Who received the phishing emails? | 40 recipients |
| [`02_click_analysis.kql`](02_click_analysis.kql) | Who clicked, and who submitted credentials? | 6 clicks, 2 credential submissions |
| [`03_credential_victim_signins.kql`](03_credential_victim_signins.kql) | Were the submitted credentials used to sign in? | 9 successful sign-ins, 2 accounts |
| [`04_attacker_ip_pivot.kql`](04_attacker_ip_pivot.kql) | Did the attacker IP touch any other account? | 2 accounts, no others |

Tables used: `CloudoraMsgTrace_CL` (message trace) and `CloudoraSignin_CL` (Entra ID sign-in logs). Both are synthetic data from the training scenario.

Queries 03 and 04 were re-run after containment to verify there was no further activity from `198.18.7.200`.

See the [full investigation](../docs/Cloudora_Phishing_Investigation_CLD-0002.pdf) for the screenshots and reasoning behind each query.
