#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
using namespace std;


// ================== Parent Class: SMS ================== //
#include <iostream>
#include <string>
using namespace std;

class SMSAnalyzer {
public:
    string senderID;
    string analyzerText;

    SMSAnalyzer(string sender, string text) {
        this->senderID = sender;
        this->analyzerText = text;
    }

    void display() {
        cout << "\n--- SMS DETAILS ---" << endl;
        cout << "Sender ID: " << senderID << endl;
        cout << "Message: " << analyzerText << endl;
    }
};

class KeywordMatcher : public virtual SMSAnalyzer {
public:
    string keywords[30] = {
        "urgent", "win", "verify", "bank", "link", "password", "click", "lottery", "prize", "free",
        "limited", "offer", "account", "delivery", "failed", "update", "suspend", "confirm", "gift", "money",
        "credit", "debit", "insurance", "loan", "bonus", "investment", "otp", "transaction", "hacked", "security"
    };

    KeywordMatcher(string sender, string text) : SMSAnalyzer(sender, text) {}

    void matchKeywords() {
        cout << "\nChecking for suspicious keywords..." << endl;
        bool found = false;
        int count = 0;

        string lowerText = analyzerText;
        for (int i = 0; i < lowerText.length(); i++) {
            lowerText[i] = tolower(lowerText[i]);
        }

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
    }
};

// ================== Derived Class: LinkAnalyzer ================== //
class LinkAnalyzer : public virtual SMSAnalyzer {
protected:
    vector<string> suspiciousDomains;
    vector<string> extractedLinks;
    int suspiciousLinkCount;

public:
    LinkAnalyzer(const string&, const string&, const string&);
    void loadSuspiciousDomains(const vector<string>& domains);
    vector<string> extractLinks();
    int analyzeLinks();
    void analyze() override;
};

// ================== Derived Class: SenderAnalyzer ================== //
class SenderAnalyzer : public virtual SMSAnalyzer {
protected:
    bool isNumericSender;
    bool isGenericSender;
    string senderReputation;

public:
    SenderAnalyzer(const string&, const string&, const string&);
    bool checkNumericSender();
    bool checkGenericSender();
    void updateSenderReputation();
    void analyze() override;
};

// ================== Multiple Derived Class: Reporter ================== //
class Reporter : protected SenderAnalyzer,              protected LinkAnalyzer,
                 protected KeywordMatcher {
protected:
    string reportFormat;
    string analysisSummary;
    map<string, int> componentScores;

public:
    Reporter(const string&, const string&, const string&);
    void setReportFormat(const string& format);
    string generateReport();
    void displayReport() const;
    void collectScores(int keywordScore, int linkScore, int senderScore);
    void analyze() override;
};

// Reporter Implementation
Reporter::Reporter(const string& content, const string& sender, const string& time)
    : SMSAnalyzer(content, sender, time),
      SenderAnalyzer(content, sender, time),
      LinkAnalyzer(content, sender, time),
      KeywordMatcher(content, sender, time),
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
    cout << analysisSummary << endl;
}

void Reporter::analyze() {
    int keywordScore = KeywordMatcher::checkKeywords();
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

// ================== EncryptionModule ================== //
class EncryptionModule {
protected:
    string encryptionKey;
    string algorithmType;

public:
    EncryptionModule(const string& key, const string& algo);
    virtual string encrypt(const string& plainText);
    virtual string decrypt(const string& cipherText);
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
    cout << "Enter SMS content: ";
    getline(cin, content);
    cout << "Enter Sender ID: ";
    getline(cin, sender);
    cout << "Enter Timestamp: ";
    getline(cin, time);

    Reporter reporter(content, sender, time);

    // Note: loading keywords/domains would be done by your teammates' implementations
    reporter.analyze();

    EncryptionModule crypto("mySecretKey", "Caesar");

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
        cin.ignore();

        if (choice == 1) {
            reporter.setReportFormat("TEXT");
            cout << reporter.generateReport() << endl;
        } else if (choice == 2) {
            reporter.setReportFormat("JSON");
            cout << reporter.generateReport() << endl;
        } else if (choice == 3) {
            reporter.setReportFormat("CSV");
            cout << reporter.generateReport() << endl;
        } else if (choice == 4) {
            string enc = crypto.encrypt(reporter.generateReport());
            cout << "Encrypted Report:\n" << enc << endl;
        } else if (choice == 5) {
            string dec = crypto.decrypt(reporter.generateReport());
            cout << "Decrypted Report:\n" << dec << endl;
        }
    } while (choice != 0);

    return 0;
}

