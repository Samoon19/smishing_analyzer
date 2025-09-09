#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <ctime>
#include <regex>
#include <algorithm>
using namespace std;

// ================== Abstract Base Class: SMSAnalyzer ================== //
// OOP Concept: Abstraction (pure virtual function)
// Encapsulation: protected members with getters/setters
class SMSAnalyzer {
protected:
    string senderID;
    string analyzerText;
    string timeStamp;
    int riskScore;

public:
    SMSAnalyzer(string sender, string text, string time)
        : senderID(sender), analyzerText(text), timeStamp(time), riskScore(0) {}

    virtual void analyze() = 0;  // Pure virtual → Abstraction & Polymorphism
    virtual ~SMSAnalyzer() {}     // Virtual destructor ensures proper cleanup

    string getSenderID() const { return senderID; }
    string getText() const { return analyzerText; }
    string getTimestamp() const { return timeStamp; }
    int getRiskScore() const { return riskScore; }
    void setRiskScore(int score) { riskScore = score; }
};

// ================== KeywordMatcher ================== //
// Inheritance: Derived class
// Static members: Object count
class KeywordMatcher : public virtual SMSAnalyzer {
private:
    string keywords[30] = {
        "urgent", "win", "verify", "bank", "link", "password", "click", "lottery", "prize", "free",
        "limited", "offer", "account", "delivery", "failed", "update", "suspend", "confirm", "gift", "money",
        "credit", "debit", "insurance", "loan", "bonus", "investment", "otp", "transaction", "hacked", "security"
    };
    static int objectCount; // Static member

public:
    KeywordMatcher(string sender, string text, string time)
        : SMSAnalyzer(sender, text, time) { objectCount++; }

    ~KeywordMatcher() override { objectCount--; } // Virtual destructor

    static int getObjectCount() { return objectCount; }

    int checkKeywords() {
        int count = 0;
        string lowerText = analyzerText;
        transform(lowerText.begin(), lowerText.end(), lowerText.begin(), ::tolower);
        for (const auto& kw : keywords)
            if (lowerText.find(kw) != string::npos) count++;
        return count;
    }

    void analyze() override { setRiskScore(getRiskScore() + checkKeywords()); }

    // Operator overloading
    friend ostream& operator<<(ostream& os, KeywordMatcher& k) {
        os << "Keywords Found: " << k.checkKeywords() << "\n";
        return os;
    }

    // Friend function
    friend void displayKeywords(KeywordMatcher& k);
};
int KeywordMatcher::objectCount = 0;

void displayKeywords(KeywordMatcher& k) {
    cout << "[Friend] Keywords in message: " << k.checkKeywords() << endl;
}

// ================== LinkAnalyzer ================== //
// Inheritance: Derived class
// Static members: Object count
class LinkAnalyzer : public virtual SMSAnalyzer {
protected:
    vector<string> suspiciousDomains;
    vector<string> extractedLinks;
    static int objectCount;

public:
    LinkAnalyzer(const string& sender, const string& text, const string& time)
        : SMSAnalyzer(sender, text, time) { objectCount++; }

    ~LinkAnalyzer() override { objectCount--; }

    static int getObjectCount() { return objectCount; }

    void loadSuspiciousDomains(const vector<string>& domains) { suspiciousDomains = domains; }

    vector<string> extractLinks() {
        extractedLinks.clear();
        regex urlRegex(R"((https?:\/\/[^\s]+))", regex::icase);
        smatch match;
        string text = analyzerText;
        while (regex_search(text, match, urlRegex)) {
            extractedLinks.push_back(match.str());
            text = match.suffix().str();
        }
        return extractedLinks;
    }

    int analyzeLinks() {
        int count = 0;
        for (const auto& link : extractedLinks)
            for (const auto& domain : suspiciousDomains)
                if (link.find(domain) != string::npos) count++;
        return count;
    }

    void analyze() override { setRiskScore(getRiskScore() + analyzeLinks() * 3); }

    // Operator overloading
    friend ostream& operator<<(ostream& os, LinkAnalyzer& l) {
        os << "Links found: " << l.extractedLinks.size() << "\n";
        if (!l.extractedLinks.empty()) {
            os << "Suspicious links: ";
            for (auto& link : l.extractedLinks) os << link << " ";
            os << "\n";
        }
        return os;
    }

    // Friend function
    friend void displayLinks(LinkAnalyzer& l);
};
int LinkAnalyzer::objectCount = 0;

void displayLinks(LinkAnalyzer& l) {
    cout << "[Friend] Total suspicious links: " << l.analyzeLinks() << endl;
}

// ================== SenderAnalyzer ================== //
// Inheritance: Derived class
// Static members: Object count
class SenderAnalyzer : public virtual SMSAnalyzer {
protected:
    bool isNumericSender;
    bool isGenericSender;
    string senderReputation;
    static int objectCount;

public:
    SenderAnalyzer(const string& sender, const string& text, const string& time)
        : SMSAnalyzer(sender, text, time), isNumericSender(false), isGenericSender(false), senderReputation("Unknown") {
        objectCount++;
    }

    ~SenderAnalyzer() override { objectCount--; }

    static int getObjectCount() { return objectCount; }

    bool checkNumericSender() {
        isNumericSender = !senderID.empty() && all_of(senderID.begin(), senderID.end(), ::isdigit);
        return isNumericSender;
    }

    bool checkGenericSender() {
        string s = senderID;
        for (char& c : s) c = toupper(c);
        isGenericSender = (s == "INFO" || s == "ALERT" || s == "BANK" || s == "SMS" || s == "NOTICE");
        return isGenericSender;
    }

    void updateSenderReputation() {
        if (isNumericSender) senderReputation = "Suspicious (Numeric ID)";
        else if (isGenericSender) senderReputation = "Suspicious (Generic ID)";
        else senderReputation = "Likely Legitimate";
    }

    void analyze() override {
        int score = 0;
        if (checkNumericSender()) score += 2;
        if (checkGenericSender()) score += 2;
        updateSenderReputation();
        setRiskScore(getRiskScore() + score);
    }

    string getReputation() const { return senderReputation; }

    // Operator overloading
    friend ostream& operator<<(ostream& os, SenderAnalyzer& s) {
        os << "Sender: " << s.senderID << " | Reputation: " << s.senderReputation << "\n";
        return os;
    }

    // Friend function
    friend void displaySender(SenderAnalyzer& s);
};
int SenderAnalyzer::objectCount = 0;

void displaySender(SenderAnalyzer& s) {
    cout << "[Friend] Sender Reputation: " << s.senderReputation << endl;
}

// ================== Reporter ================== //
// Multiple Inheritance: combines all analyzers
// Operator overloading and friend class
class UserFeedback;

class Reporter : public SenderAnalyzer, public LinkAnalyzer, public KeywordMatcher {
protected:
    string reportFormat;
    string analysisSummary;
    map<string, int> componentScores;
    static int reportCount;

public:
    Reporter(const string& sender, const string& text, const string& time)
        : SMSAnalyzer(sender, text, time), SenderAnalyzer(sender, text, time),
          LinkAnalyzer(sender, text, time), KeywordMatcher(sender, text, time),
          reportFormat("TEXT"), analysisSummary("") {
        reportCount++;
    }

    ~Reporter() override { cout << "[Destructor] Reporter object destroyed.\n"; }

    static int getReportCount() { return reportCount; }

    void setReportFormat(const string& format) { reportFormat = format; }

    void collectScores(int keywordScore, int linkScore, int senderScore) {
        componentScores["Keyword"] = keywordScore;
        componentScores["Link"] = linkScore;
        componentScores["Sender"] = senderScore;
        setRiskScore(keywordScore + linkScore + senderScore);
    }

    string generateReport() const {
        ostringstream report;
        if (reportFormat == "JSON") {
            report << "{\n"
                   << "  \"SenderID\": \"" << getSenderID() << "\",\n"
                   << "  \"Timestamp\": \"" << getTimestamp() << "\",\n"
                   << "  \"RiskScore\": " << getRiskScore() << ",\n"
                   << "  \"ComponentScores\": {\n"
                   << "    \"Keyword\": " << componentScores.at("Keyword") << ",\n"
                   << "    \"Link\": " << componentScores.at("Link") << ",\n"
                   << "    \"Sender\": " << componentScores.at("Sender") << "\n"
                   << "  },\n"
                   << "  \"Summary\": \"" << analysisSummary << "\"\n"
                   << "}";
        } else if (reportFormat == "CSV") {
            report << "SenderID,Timestamp,RiskScore,KeywordScore,LinkScore,SenderScore,Summary\n";
            report << getSenderID() << "," << getTimestamp() << "," << getRiskScore() << ","
                   << componentScores.at("Keyword") << "," << componentScores.at("Link") << ","
                   << componentScores.at("Sender") << ",\"" << analysisSummary << "\"\n";
        } else {
            report << "=== SMS Security Report ===\n";
            report << "Sender: " << getSenderID() << "\n";
            report << "Time: " << getTimestamp() << "\n";
            report << "Risk Score: " << getRiskScore() << "\n";
            report << "Keyword Score: " << componentScores.at("Keyword") << "\n";
            report << "Link Score: " << componentScores.at("Link") << "\n";
            report << "Sender Score: " << componentScores.at("Sender") << "\n";
            report << "Summary: " << analysisSummary << "\n";
        }
        return report.str();
    }

    void analyze() override {
        int keywordScore = KeywordMatcher::checkKeywords();
        LinkAnalyzer::extractLinks();
        int linkScore = LinkAnalyzer::analyzeLinks();
        bool isNumeric = SenderAnalyzer::checkNumericSender();
        bool isGeneric = SenderAnalyzer::checkGenericSender();
        int senderScore = (isNumeric ? 2 : 0) + (isGeneric ? 2 : 0);
        collectScores(keywordScore, linkScore, senderScore);
        ostringstream summary;
        summary << "Message from " << getSenderID()
                << " scored " << getRiskScore() << " risk points.";
        analysisSummary = summary.str();
    }

    friend ostream& operator<<(ostream& os, const Reporter& r) {
        os << r.generateReport();
        return os;
    }

    friend class UserFeedback; // Friend class
};
int Reporter::reportCount = 0;

// ================== UserFeedback ================== //
// Friend class access
class UserFeedback {
public:
    void recordFeedback(const Reporter& r, bool userJudgment) {
        cout << "\n[Feedback] System predicted risk score: " << r.riskScore
             << " | User says spam = " << (userJudgment ? "Yes" : "No") << endl;
    }
};

// ================== Encryption Module ================== //
// Fixed Caesar Cipher
class EncryptionModule {
protected:
    string encryptionKey;
    string algorithmType;

public:
    EncryptionModule(const string& key, const string& algo)
        : encryptionKey(key), algorithmType(algo) {}

    string encrypt(const string& plainText) {
        string result = plainText;
        int shift = encryptionKey.length() % 26;
        for (char& c : result) {
            if (isalpha(c)) {
                char base = isupper(c) ? 'A' : 'a';
                c = ((c - base + shift) % 26) + base;
            }
        }
        return result;
    }

    string decrypt(const string& cipherText) {
        string result = cipherText;
        int shift = encryptionKey.length() % 26;
        for (char& c : result) {
            if (isalpha(c)) {
                char base = isupper(c) ? 'A' : 'a';
                c = ((c - base - shift + 26) % 26) + base;
            }
        }
        return result;
    }

    friend void encryptionStats(EncryptionModule& e);
};

void encryptionStats(EncryptionModule& e) {
    cout << "[Friend] Encryption key: " << e.encryptionKey
         << " | Algorithm: " << e.algorithmType << endl;
}

// ================== MAIN ================== //
int main() {
    string content, sender, time;
    cout << "Enter SMS content: ";
    getline(cin, content);
    cout << "Enter Sender ID: ";
    getline(cin, sender);
    cout << "Enter Timestamp: ";
    getline(cin, time);

    Reporter reporter(sender, content, time);
    vector<string> domains = {"phish.com", "malware.net", "fakebank.org"};
    reporter.loadSuspiciousDomains(domains);
    reporter.analyze();

    EncryptionModule crypto("mySecretKey", "Caesar");
    UserFeedback feedback;

    int choice;
    do {
        cout << "\n===== MAIN MENU =====\n";
        cout << "1. Show Report (TEXT)\n";
        cout << "2. Show Report (JSON)\n";
        cout << "3. Show Report (CSV)\n";
        cout << "4. Encrypt Report\n";
        cout << "5. Decrypt Report\n";
        cout << "6. Give Feedback\n";
        cout << "7. Show Report Count\n";
        cout << "8. Show Friend Details\n";
        cout << "9. Show Analyzer Object Counts\n";
        cout << "0. Exit\n";
        cout << "Choose: ";
        cin >> choice;
        cin.ignore();

        if (choice == 1) { reporter.setReportFormat("TEXT"); cout << reporter << endl; }
        else if (choice == 2) { reporter.setReportFormat("JSON"); cout << reporter << endl; }
        else if (choice == 3) { reporter.setReportFormat("CSV"); cout << reporter << endl; }
        else if (choice == 4) { 
            string enc = crypto.encrypt(reporter.generateReport());
            cout << "Encrypted Report:\n" << enc << endl;
        }
        else if (choice == 5) { 
            string enc = crypto.encrypt(reporter.generateReport()); // encrypt first to test decrypt
            string dec = crypto.decrypt(enc);
            cout << "Decrypted Report:\n" << dec << endl;
        }
        else if (choice == 6) { 
            bool userJudgment; 
            cout << "Do you think this SMS is spam? (1=Yes, 0=No): "; 
            cin >> userJudgment; 
            feedback.recordFeedback(reporter, userJudgment);
        }
        else if (choice == 7) { cout << "Total reports generated: " << Reporter::getReportCount() << endl; }
        else if (choice == 8) { displayKeywords(reporter); displayLinks(reporter); displaySender(reporter); encryptionStats(crypto); }
        else if (choice == 9) { 
            cout << "KeywordMatcher objects: " << KeywordMatcher::getObjectCount() 
                 << "\nLinkAnalyzer objects: " << LinkAnalyzer::getObjectCount() 
                 << "\nSenderAnalyzer objects: " << SenderAnalyzer::getObjectCount() 
                 << "\nReporter objects: " << Reporter::getReportCount() << endl; 
        }
    } while (choice != 0);

    return 0;
}

