# Smishing Analyzer (Java-based SMS Phishing Detection System)

## Overview
Smishing Analyzer is a Java-based application designed to detect and analyze potentially malicious SMS messages. The system combines encryption, keyword detection, link analysis, sender evaluation, and reporting functionality to provide a comprehensive SMS phishing detection solution.

## Features
- **Keyword Matching:** Detect suspicious words or phrases in SMS messages.
- **Link Analysis:** Check URLs against known malicious domains.
- **Sender Evaluation:** Assess sender credibility based on historical data.
- **Encryption:** Secure storage and processing of messages.
- **Reporting:** Generate detailed analysis reports.
- **User Feedback:** Collect feedback to improve detection accuracy.
- **Firebase Integration:** Store messages and analysis results centrally.

## Technology Stack
- Java 8+
- Firebase Realtime Database
- Java Encryption libraries

## Project Structure
- **Main.java:** Entry point of the application.
- **SmsAnalyzer.java:** Core analysis engine integrating all modules.
- **EncryptionModule.java:** Handles encryption of message data.
- **FirebaseManager.java:** Firebase database operations.
- **KeywordMatcher.java:** Suspicious keyword detection.
- **LinkAnalyzer.java:** Malicious URL detection.
- **SenderAnalyzer.java:** Sender credibility evaluation.
- **Reporter.java:** Generates structured analysis reports.
- **UserFeedback.java:** User feedback collection.
- **LICENSE:** Open-source license information.
- **README.md:** Project documentation.
- **research_articles.md:** References used in project research.

## Setup & Installation
1. Clone the repository:
   ```bash
   git clone <repository_url>
   ```
2. Ensure Java 8+ is installed.
3. Set up Firebase and update the configuration in `FirebaseManager.java`.
4. Compile the project:
   ```bash
   javac *.java
   ```
5. Run the application:
   ```bash
   java Main
   ```

## Usage
1. Input the SMS message when prompted.
2. The system will analyze for keywords, links, and sender credibility.
3. Analysis report will be displayed and stored in Firebase.
4. Optionally, provide user feedback to refine detection.

## Sample Output
- Flagged keywords: "urgent", "verify account"
- Malicious links detected: https://malicious.example.com
- Sender credibility: Low
- Report generated: `report_20251017.docx`

## Contribution
Contributions are welcome. Please fork the repository and submit pull requests.

## License
Refer to LICENSE file for licensing information.
