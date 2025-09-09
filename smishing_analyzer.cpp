#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <ctime>
#include <regex>
#include <algorithm>
#include <limits>
using namespace std;

// ================== Parent Class: SMS ================== //
class SMSAnalyzer {
public:
    string senderID;
    string analyzerText;
    string timeStamp;
    int riskScore = 0;

    SMSAnalyzer(string sender, string text, string time)
    : senderID(sender), analyzerText(text), timeStamp(time) {}

    string getSenderID() const { return senderID; }
    string getTimestamp() const { return timeStamp; }
    string getAnalyzerText() const { return analyzerText; }
    int getRiskScore() const { return riskScore; }
    void setRiskScore(int score) { riskScore = score; }

    void display() {
        cout << "\n--- SMS DETAILS ---" << endl;
        cout << "Sender ID: " << senderID << endl;
        cout << "Message: " << analyzerText << endl;
        cout << "Received At: " << timeStamp << endl;
    }

    // abstract method → makes SMSAnalyzer abstract
    virtual void analyze() = 0;
    virtual ~SMSAnalyzer() = default; // Virtual destructor for proper cleanup
};

// ================== Derived Class: KeywordMatcher ================== //
class KeywordMatcher : public virtual SMSAnalyzer {
public:
    string keywords[30] = {
        "urgent", "win", "verify", "bank", "link", "password", "click", "lottery", "prize", "free",
        "limited", "offer", "account", "delivery", "failed", "update", "suspend", "confirm", "gift", "money",
        "credit", "debit", "insurance", "loan", "bonus", "investment", "otp", "transaction", "hacked", "security"
    };

    KeywordMatcher(string sender, string text, string time)
        : SMSAnalyzer(sender, text, time) {}

    int checkKeywords() {
        cout << "\nChecking for suspicious keywords..." << endl;
        bool found = false;
        int count = 0;

        string lowerText = analyzerText;
        transform(lowerText.begin(), lowerText.end(), lowerText.begin(), ::tolower);

        for (int i = 0; i < 30; i++) {
            if (lowerText.find(keywords[i]) != string::npos) {
                cout << "Found keyword: " << keywords[i] << endl;
                found = true;
                count++;
            }
        }

        if (found) {
            cout << "ALERT: " << count << " suspicious keyword(s) found!" << endl;
        } else {
            cout << "No suspicious keywords found." << endl;
        }
        return count;
    }

    void analyze() override {
        int score = checkKeywords();
        setRiskScore(score);
    }
};

// ================== Derived Class: LinkAnalyzer ================== //
class LinkAnalyzer : public virtual SMSAnalyzer {
protected:
    vector<string> suspiciousDomains;
    vector<string> extractedLinks;
    vector<string> flaggedLinks; // Moved from global to class member
    int suspiciousLinkCount;

public:
    LinkAnalyzer(string sender, string text, string time); // Fixed parameter order
    void loadSuspiciousDomains(const vector<string>& domains);
    vector<string> extractLinks();
    int analyzeLinks();
    void analyze() override;
};

// LinkAnalyzer Implementation
LinkAnalyzer::LinkAnalyzer(string sender, string text, string time)
    : SMSAnalyzer(sender, text, time), suspiciousLinkCount(0) {
    // Load default suspicious domains
    suspiciousDomains = {
        "bit.ly", "tinyurl.com", "short.link", "suspicious-bank.com", 
        "fake-lottery.net", "phishing-site.org", "malware-download.com"
    };
}

void LinkAnalyzer::loadSuspiciousDomains(const vector<string>& domains) {
    suspiciousDomains = domains;
}

vector<string> LinkAnalyzer::extractLinks() {
    extractedLinks.clear();
    regex urlRegex(R"((https?:\/\/[^\s]+))", regex::icase);
    smatch match;
    string text = getAnalyzerText();

    while (regex_search(text, match, urlRegex)) {
        extractedLinks.push_back(match.str());
        text = match.suffix().str();
    }
    
    cout << "\nFound " << extractedLinks.size() << " link(s) in message." << endl;
    return extractedLinks;
}

int LinkAnalyzer::analyzeLinks() {
    suspiciousLinkCount = 0;
    flaggedLinks.clear();
    
    for (const auto& link : extractedLinks) {
        for (const auto& domain : suspiciousDomains) {
            if (link.find(domain) != string::npos) {
                flaggedLinks.push_back(link);
                suspiciousLinkCount++;
                cout << "SUSPICIOUS LINK FOUND: " << link << endl;
                break; // Avoid double-counting same link
            }
        }
    }
    return suspiciousLinkCount;
}
void LinkAnalyzer::analyze() {
    extractLinks();
    int score = analyzeLinks();
    setRiskScore(score * 3);  // weight suspicious links higher
}

// ================== Derived Class: SenderAnalyzer ================== //
class SenderAnalyzer : public virtual SMSAnalyzer {
protected:
    bool isNumericSender;
    bool isGenericSender;
    string senderReputation;

public:
    SenderAnalyzer(string sender, string text, string time); // Fixed parameter order
    bool checkNumericSender();
    bool checkGenericSender();
    void updateSenderReputation();
    void analyze() override;
};

// SenderAnalyzer Implementation
SenderAnalyzer::SenderAnalyzer(string sender, string text, string time)
    : SMSAnalyzer(sender, text, time),
      isNumericSender(false), isGenericSender(false), senderReputation("Unknown") {}

bool SenderAnalyzer::checkNumericSender() {
    isNumericSender = !getSenderID().empty() &&
                      all_of(getSenderID().begin(), getSenderID().end(), ::isdigit);
    return isNumericSender;
}

bool SenderAnalyzer::checkGenericSender() {
    string s = getSenderID();
    transform(s.begin(), s.end(), s.begin(), ::toupper);

    isGenericSender = (s == "INFO" || s == "ALERT" || s == "BANK" ||
                       s == "SMS" || s == "NOTICE");
    return isGenericSender;
}

void SenderAnalyzer::updateSenderReputation() {
    if (isNumericSender)
        senderReputation = "Suspicious (Numeric ID)";
    else if (isGenericSender)
        senderReputation = "Suspicious (Generic ID)";
    else
        senderReputation = "Likely Legitimate";
}

void SenderAnalyzer::analyze() {
    int score = 0;
    cout << "\nAnalyzing sender: " << getSenderID() << endl;
    
    if (checkNumericSender()) {
        cout << "Sender uses numeric ID - SUSPICIOUS" << endl;
        score += 2;
    }
    if (checkGenericSender()) {
        cout << "Sender uses generic ID - SUSPICIOUS" << endl;
        score += 2;
    }
    updateSenderReputation();
    cout << "Sender reputation: " << senderReputation << endl;
    setRiskScore(score);
}

// ================== Multiple Derived Class: Reporter ================== //
class Reporter : protected SenderAnalyzer,
                 protected LinkAnalyzer,
                 protected KeywordMatcher {
protected:
    string reportFormat;
    string analysisSummary;
    map<string, int> componentScores;

public:
    Reporter(string sender, string text, string time); // Fixed parameter order
    void setReportFormat(const string& format);
    string generateReport();
    void displayReport() const;
    void collectScores(int keywordScore, int linkScore, int senderScore);
    void analyze() override;
};

// Reporter Implementation
Reporter::Reporter(string sender, string text, string time)
    : SMSAnalyzer(sender, text, time),
      SenderAnalyzer(sender, text, time),
      LinkAnalyzer(sender, text, time),
      KeywordMatcher(sender, text, time),
      reportFormat("TEXT"), analysisSummary("") {}

void Reporter::setReportFormat(const string& format) {
    reportFormat = format;
}

void Reporter::collectScores(int keywordScore, int linkScore, int senderScore) {
    componentScores["Keyword"] = keywordScore;
    componentScores["Link"] = linkScore;
    componentScores["Sender"] = senderScore;

    int total = keywordScore + linkScore + senderScore;
    setRiskScore(total);
}

string Reporter::generateReport() {
    ostringstream report;

    if (reportFormat == "JSON") {
        report << "{\n"
               << "  \"SenderID\": \"" << getSenderID() << "\",\n"
               << "  \"Timestamp\": \"" << getTimestamp() << "\",\n"
               << "  \"RiskScore\": " << getRiskScore() << ",\n"
               << "  \"ComponentScores\": {\n"
               << "    \"Keyword\": " << componentScores["Keyword"] << ",\n"
               << "    \"Link\": " << componentScores["Link"] << ",\n"
               << "    \"Sender\": " << componentScores["Sender"] << "\n"
               << "  },\n"
               << "  \"Summary\": \"" << analysisSummary << "\"\n"
               << "}";
    } else if (reportFormat == "CSV") {
        report << "SenderID,Timestamp,RiskScore,KeywordScore,LinkScore,SenderScore,Summary\n";
        report << getSenderID() << ","
               << getTimestamp() << ","
               << getRiskScore() << ","
               << componentScores["Keyword"] << ","
               << componentScores["Link"] << ","
               << componentScores["Sender"] << ","
               << "\"" << analysisSummary << "\"\n";
    } else {
        report << "=== SMS Security Report ===\n";
        report << "Sender: " << getSenderID() << "\n";
        report << "Time: " << getTimestamp() << "\n";
        report << "Risk Score: " << getRiskScore() << "\n";
        report << "Keyword Score: " << componentScores["Keyword"] << "\n";
        report << "Link Score: " << componentScores["Link"] << "\n";
        report << "Sender Score: " << componentScores["Sender"] << "\n";
        report << "Summary: " << analysisSummary << "\n";
    }
    return report.str();
}

void Reporter::displayReport() const {
    cout << generateReport() << endl;
}

void Reporter::analyze() {
    cout << "\n=== STARTING SMS ANALYSIS ===" << endl;
    
    // Perform individual analyses
    int keywordScore = KeywordMatcher::checkKeywords();
    
    LinkAnalyzer::extractLinks();
    int linkScore = LinkAnalyzer::analyzeLinks();
    
    bool isNumeric = SenderAnalyzer::checkNumericSender();
    bool isGeneric = SenderAnalyzer::checkGenericSender();
    SenderAnalyzer::updateSenderReputation();
    
    int senderScore = (isNumeric ? 2 : 0) + (isGeneric ? 2 : 0);

    collectScores(keywordScore, linkScore, senderScore);

    // Generate summary
    ostringstream summary;
    summary << "Message from " << getSenderID()
            << " scored " << getRiskScore() << " risk points. ";
    
    if (getRiskScore() >= 7) {
        summary << "HIGH RISK - Likely spam/phishing.";
    } else if (getRiskScore() >= 4) {
        summary << "MEDIUM RISK - Suspicious content detected.";
    } else {
        summary << "LOW RISK - Appears legitimate.";
    }
    
    analysisSummary = summary.str();
    cout << "\n" << analysisSummary << endl;
}

// ================== EncryptionModule ================== //
class EncryptionModule {
protected:
    string encryptionKey;
    string algorithmType;

public:
    EncryptionModule(const string& key, const string& algo);
    virtual string encrypt(const string& plainText);
    virtual string decrypt(const string& cipherText);
    virtual ~EncryptionModule() = default;
};

// EncryptionModule Implementation
EncryptionModule::EncryptionModule(const string& key, const string& algo)
    : encryptionKey(key), algorithmType(algo) {}

string EncryptionModule::encrypt(const string& plainText) {
    string result = plainText;
    int shift = encryptionKey.length() % 26;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            c = (c - base + shift) % 26 + base;
        }
    }
    return result;
}

string EncryptionModule::decrypt(const string& cipherText) {
    string result = cipherText;
    int shift = encryptionKey.length() % 26;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            c = (c - base - shift + 26) % 26 + base;
        }
    }
    return result;
}

// ================== Main Menu ================== //
int main() {
    string content, sender, time;
    
    cout << "=== SMS Security Analyzer ===" << endl;
    cout << "Enter SMS content: ";
    getline(cin, content);
    cout << "Enter Sender ID: ";
    getline(cin, sender);
    cout << "Enter Timestamp: ";
    getline(cin, time);

    // Create reporter with corrected parameter order
    Reporter reporter(sender, content, time);

    // Perform analysis
    reporter.analyze();

    // Create encryption module
    EncryptionModule crypto("mySecretKey", "Caesar");
    string lastEncrypted;
    int choice;
    do {
        cout << "\n===== MAIN MENU =====\n";
        cout << "1. Show Report (TEXT)\n";
        cout << "2. Show Report (JSON)\n";
        cout << "3. Show Report (CSV)\n";
        cout << "4. Encrypt Report\n";
        cout << "5. Decrypt Report\n";
        cout << "0. Exit\n";
        cout << "Choose: ";
        cin >> choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch(choice) {
            case 1:
                reporter.setReportFormat("TEXT");
                cout << "\n" << reporter.generateReport() << endl;
                break;
            case 2:
                reporter.setReportFormat("JSON");
                cout << "\n" << reporter.generateReport() << endl;
                break;
            case 3:
                reporter.setReportFormat("CSV");
                cout << "\n" << reporter.generateReport() << endl;
                break;
            

            case 4:
                reporter.setReportFormat("TEXT");
                lastEncrypted = crypto.encrypt(reporter.generateReport());
                cout << "\nEncrypted Report:\n" << lastEncrypted << endl;
                break;
            case 5:
                if (!lastEncrypted.empty()) {
                    cout << "\nDecrypted Report:\n" << crypto.decrypt(lastEncrypted) << endl;
                } 
                else {
                    cout << "\nNo encrypted report found!\n";
                }
            break;

            case 0:
                cout << "Goodbye! Stay safe from spam!" << endl;
                break;
            default:
                cout << "Invalid choice. Please try again." << endl;
        }
    } while (choice != 0);

    return 0;
}

