## SMS Security Analyzer

A C++ program for analyzing SMS messages to detect potential spam, phishing, or suspicious content. Utilizes OOP concepts, keyword detection, link analysis, and sender evaluation. Reports can be generated in multiple formats, encrypted, saved, and reviewed later.

## Features

1. Keyword Analysis: Detects common spam and phishing keywords in the message.

2. Link Analysis: Extracts links and flags suspicious domains.

3. Sender Analysis: Evaluates sender IDs for numeric or generic patterns.

4. Risk Scoring: Calculates a total risk score based on message content, links, and sender reputation.

5. Multiple Report Formats: Generates reports in TEXT, JSON, and CSV formats.

6. Report History: View, save, or revisit past generated reports.

7. Encryption/Decryption: Securely encrypt and decrypt reports using a simple Caesar cipher.

8. User Feedback: Option for users to indicate if a message is spam.

## Classes

- SMSAnalyzer: Abstract base class for SMS analysis (abstraction & polymorphism).

- KeywordMatcher: Checks for suspicious keywords.

- LinkAnalyzer: Extracts links and evaluates suspicious domains.

- SenderAnalyzer: Checks sender type and updates reputation.

- Reporter: Combines all analyses and generates reports.

- EncryptionModule: Provides simple Caesar cipher encryption/decryption.

- UserFeedback: Records user judgments on messages.
