package com.smishing;

public interface SmsAnalyzer {
    void analyze();
    int getRiskScore();
    void setRiskScore(int score);
}