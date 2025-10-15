package com.smishing;

public class SenderAnalyzer {
    private String senderId;
    private int riskScore;
    private String senderReputation;

    public SenderAnalyzer(String senderId) {
        this.senderId = senderId;
        this.riskScore = 0;
        this.senderReputation = "Unknown";
    }

    public boolean checkNumericSender() {
        return senderId != null && senderId.matches("\\d+");
    }

    public boolean checkGenericSender() {
        String s = senderId.toUpperCase();
        return s.equals("INFO") || s.equals("ALERT") || s.equals("BANK") || s.equals("SMS") || s.equals("NOTICE");
    }

    public void updateSenderReputation() {
        if (checkNumericSender()) {
            senderReputation = "Suspicious (Numeric ID)";
            riskScore += 2;
        } else if (checkGenericSender()) {
            senderReputation = "Suspicious (Generic ID)";
            riskScore += 2;
        } else {
            senderReputation = "Likely Legitimate";
        }
    }

    public void analyze() {
        updateSenderReputation();
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getReputation() {
        return senderReputation;
    }
}