# Agentic GenAI Security Accelerator

The Agentic GenAI Security Accelerator is an AWS-native demo project designed to help customers understand, score, and improve their cloud security posture using AWS security services, Amazon S3, Amazon Bedrock, MCP, and a customer-facing AI dashboard.

The accelerator centralizes AWS security posture findings, normalizes them, calculates a 0–5 security maturity score, and uses agentic AI to explain risks, recommend remediation, and help customers understand what actions will improve their score.

## Goal

The goal of this project is to move customers from static security findings to AI-guided security posture improvement.

Customers should be able to ask questions such as:

- Why is my score 2.7?
- What are my highest-risk findings?
- What will bring me to a 5?
- Do I need AWS WAF?
- Which S3 buckets are exposed?
- What should I fix first?
- Create a 30/60/90 day security roadmap.

## High-Level Architecture

Customer AWS Account  
→ AWS Security Assessment Layer  
→ Amazon S3 Security Findings Lake  
→ Ingestion Lambda  
→ DynamoDB Findings Store  
→ 0–5 Scoring Engine  
→ Amazon Bedrock Agents  
→ MCP Validation Layer  
→ Dashboard + AI Chat + Reports

## Core Capabilities

- AWS security posture findings ingestion
- Amazon S3 findings lake
- Normalized finding schema
- 0–5 security maturity scoring
- Pillar-level scoring
- AI-generated business impact analysis
- AI remediation guidance
- MCP-based AWS documentation and context validation
- Customer-facing dashboard
- AI security chat
- Dry-run remediation workflow
- Human approval requirement
- Report generation

## Security Maturity Pillars

1. Identity & Governance
2. Visibility, Detection & Response
3. Data Protection
4. Compliance & Audit Readiness
5. Generative Security Intelligence

## Governance Principles

- Read-only by default
- Dry-run remediation only
- Human approval before action
- CloudWatch audit logging
- S3 and DynamoDB encryption
- Least-privilege IAM
- No customer data or secrets committed to the repository

## Project Status

This project is currently in the foundation phase.

Current work:
- GitHub repository created
- GitHub Pages landing page created
- Project documentation being structured
- Kiro will be used for spec-driven development

## Planned Phases

### Phase 1: Project Foundation
Create repo structure, documentation, requirements, design, and implementation tasks.

### Phase 2: Findings Lake
Create the S3 findings lake structure and sample findings.

### Phase 3: Ingestion
Build Lambda-based ingestion and normalization.

### Phase 4: Scoring Engine
Calculate 0–5 maturity scores and score improvement opportunities.

### Phase 5: Dashboard
Build the customer-facing dashboard.

### Phase 6: AI Chat
Use Amazon Bedrock to answer questions about findings and maturity score.

### Phase 7: MCP Validation
Use MCP to validate recommendations against AWS documentation and approved context.

### Phase 8: Reports
Generate executive summaries and 30/60/90 day roadmaps.

## GitHub Pages

Project site:

https://lxrsd.github.io/agentic-genai-security-accelerator/
