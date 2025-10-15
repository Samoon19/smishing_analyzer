package com.smishing;

import java.util.Arrays;
import java.util.List;

public class KeywordMatcher {
    private String analyzerText;
    private int riskScore;

    private final List<String> keywords = Arrays.asList(
        "urgent", "win", "verify", "bank", "link", "password", "click", "lottery", "prize", "free",
        "limited", "offer", "account", "delivery", "failed", "update", "suspend", "confirm", "gift", "money",
        "credit", "debit", "insurance", "loan", "bonus", "investment", "otp", "transaction", "hacked", "security"
    );

    public KeywordMatcher(String text) {
        this.analyzerText = text;
        this.riskScore = 0;
    }

    public int checkKeywords() {
        int count = 0;
        String lowerText = analyzerText.toLowerCase();
        for (String kw : keywords) {
            if (lowerText.contains(kw)) {
                count++;
            }
        }
        return count;
    }

    public void analyze() {
        int keywordCount = checkKeywords();
        int score = (keywordCount >= 5) ? 10 : keywordCount;
        setRiskScore(score);
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int score) {
        this.riskScore = score;
    }
}
