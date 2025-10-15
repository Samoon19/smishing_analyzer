package com.smishing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LinkAnalyzer {
    private String analyzerText;
    private int riskScore;

    private List<String> suspiciousDomains;
    private List<String> extractedLinks = new ArrayList<>();
    private List<String> flaggedLinks = new ArrayList<>();

    public LinkAnalyzer(String text) {
        this.analyzerText = text;
        this.riskScore = 0;
        // Load default suspicious domains
        suspiciousDomains = Arrays.asList(
            "bit.ly", "tinyurl.com", "short.link", "suspicious-bank.com",
            "fake-lottery.net", "phishing-site.org", "malware-download.com"
        );
    }

    public void loadSuspiciousDomains(List<String> domains) {
        this.suspiciousDomains = domains;
    }

    public List<String> extractLinks() {
        extractedLinks.clear();
        Pattern urlPattern = Pattern.compile("(https?://[\\S]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = urlPattern.matcher(analyzerText);
        while (matcher.find()) {
            extractedLinks.add(matcher.group());
        }
        return extractedLinks;
    }

    public int analyzeLinks() {
        int suspiciousLinkCount = 0;
        flaggedLinks.clear();

        for (String link : extractedLinks) {
            for (String domain : suspiciousDomains) {
                if (link.contains(domain)) {
                    flaggedLinks.add(link);
                    suspiciousLinkCount++;
                    System.out.println("SUSPICIOUS LINK FOUND: " + link);
                    break;
                }
            }
        }
        return suspiciousLinkCount;
    }

    public void analyze() {
        extractLinks();
        setRiskScore(analyzeLinks() * 3);
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int score) {
        this.riskScore = score;
    }
}