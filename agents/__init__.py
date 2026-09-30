"""JOCKY central-management fabric (SIH26148, PS -"central management").

Security-analysis tooling for authorized assessments: a controller that
queues `.jxp` payloads to many clients, a polling client that decrypts and
executes them *in RAM only*, and transport channels (domain-fronting style
and cloud-API dead-drop) per the PS requirement that management traffic be
routed through trusted cloud infrastructure / CDNs.
"""