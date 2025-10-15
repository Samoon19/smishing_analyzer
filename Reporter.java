package com.smishing;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.FileWriter;
import java.io.IOException;

public class Reporter {
    private String senderId;
    private String text;
    private String timestamp;
    private String reportFormat;
    private String analysisSummary;
    private int totalRiskScore;
    private Map<String, Integer> componentScores = new HashMap<>();

    private KeywordMatcher keywordMatcher;
    private LinkAnalyzer linkAnalyzer;
    private SenderAnalyzer senderAnalyzer;

    public Reporter(String senderId, String text, String timestamp, List<String> suspiciousDomains) {
        this.senderId = senderId;
        this.text = text;
        this.timestamp = timestamp;
        this.reportFormat = "TEXT";
        
        this.keywordMatcher = new KeywordMatcher(text);
        this.linkAnalyzer = new LinkAnalyzer(text);
        this.senderAnalyzer = new SenderAnalyzer(senderId);

        this.linkAnalyzer.loadSuspiciousDomains(suspiciousDomains);
    }
    
    public void setReportFormat(String format) {
        this.reportFormat = format;
    }
    
    public int getRiskScore() {
        return totalRiskScore;
    }
    
    public String getSenderId() {
        return senderId;
    }

    public String getText() {
        return text;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void analyze() {
        System.out.println("\n=== STARTING SMS ANALYSIS ===");
        
        keywordMatcher.analyze();
        linkAnalyzer.analyze();
        senderAnalyzer.analyze();
        
        componentScores.put("Keyword", keywordMatcher.getRiskScore());
        componentScores.put("Link", linkAnalyzer.getRiskScore());
        componentScores.put("Sender", senderAnalyzer.getRiskScore());

        totalRiskScore = keywordMatcher.getRiskScore() + linkAnalyzer.getRiskScore() + senderAnalyzer.getRiskScore();

        this.analysisSummary = getAnalysisSummary();
        System.out.println("\n" + this.analysisSummary);
    }

    private String getAnalysisSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("Message from ").append(senderId).append(" scored ").append(totalRiskScore).append(" risk points. ");
        
        if (totalRiskScore >= 7) {
            summary.append("HIGH RISK - Likely spam/phishing.");
        } else if (totalRiskScore >= 4) {
            summary.append("MEDIUM RISK - Suspicious content detected.");
        } else {
            summary.append("LOW RISK - Appears legitimate.");
        }
        
        return summary.toString();
    }
    
    public String generateReport() {
        if ("JSON".equalsIgnoreCase(reportFormat)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            Map<String, Object> reportData = new HashMap<>();
            reportData.put("SenderID", senderId);
            reportData.put("Timestamp", timestamp);
            reportData.put("RiskScore", totalRiskScore);
            reportData.put("ComponentScores", componentScores);
            reportData.put("Summary", analysisSummary);
            return gson.toJson(reportData);
        } else if ("CSV".equalsIgnoreCase(reportFormat)) {
            return String.format("SenderID,Timestamp,RiskScore,KeywordScore,LinkScore,SenderScore,Summary\n%s,%s,%d,%d,%d,%d,\"%s\"",
                senderId, timestamp, totalRiskScore,
                componentScores.getOrDefault("Keyword", 0),
                componentScores.getOrDefault("Link", 0),
                componentScores.getOrDefault("Sender", 0),
                analysisSummary);
        } else {
            return String.format("=== SMS Security Report ===\nSender: %s\nTime: %s\nRisk Score: %d\nKeyword Score: %d\nLink Score: %d\nSender Score: %d\nSummary: %s",
                senderId, timestamp, totalRiskScore,
                componentScores.getOrDefault("Keyword", 0),
                componentScores.getOrDefault("Link", 0),
                componentScores.getOrDefault("Sender", 0),
                analysisSummary);
        }
    }
    
    public void saveReportToFile(String filename) {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(generateReport());
            System.out.println("Report saved to " + filename);
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
    }
}