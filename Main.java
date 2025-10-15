package com.smishing;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Main {
    public static void main(String[] args) throws IOException {
        System.out.println("Welcome to the Smishing Analyzer!");

        EncryptionModule crypto = new EncryptionModule("mySecretKey", "Caesar");
        Reporter reporter = null;
        UserFeedback feedback = new UserFeedback();

        // Initialize Firebase
        // NOTE: Replace these placeholder values with your actual Firebase project info
        String databaseUrl = "https://smishinganalyzer-default-rtdb.firebaseio.com";
        String serviceAccountKeyPath = "C:\\Users\\M.Salai Neranjana\\OneDrive\\Desktop\\pleaseeee\\smishing\\serviceAccountKey.json"; // <-- Update this path with your file's name
        FirebaseManager fbManager = new FirebaseManager(databaseUrl, serviceAccountKeyPath);

        int choice;
        do {
            System.out.println("\n");
            System.out.println("========================================");
            System.out.println("||              MAIN MENU             ||");
            System.out.println("========================================");
            System.out.println("|| 1. Create New Report               ||");
            System.out.println("|| 2. Show Latest Report (TEXT)       ||");
            System.out.println("|| 3. Show Latest Report (JSON)       ||");
            System.out.println("|| 4. Show Latest Report (CSV)        ||");
            System.out.println("|| 5. Encrypt Latest Report           ||");
            System.out.println("|| 6. Decrypt Last Encrypted Report   ||");
            System.out.println("|| 7. Save Latest Report to File      ||");
            System.out.println("|| 8. User Feedback                   ||");
            System.out.println("|| 0. Exit                            ||");
            System.out.println("========================================");
            System.out.print("Choose: ");

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine();
            try {
                choice = Integer.parseInt(line);
            } catch (NumberFormatException e) {
                choice = -1; // Invalid input
            }

            switch(choice) {
                case 1:
                    System.out.print("Enter SMS content: ");
                    String content = reader.readLine();
                    System.out.print("Enter Sender ID: ");
                    String sender = reader.readLine();
                    System.out.print("Enter Timestamp: ");
                    String time = reader.readLine();

                    List<String> suspiciousDomains = Arrays.asList("phish.com", "malware.net", "fakebank.org");
                    reporter = new Reporter(sender, content, time, suspiciousDomains);
                    reporter.analyze();
                    break;
                case 2:
                    if (reporter != null) {
                        reporter.setReportFormat("TEXT");
                        System.out.println(reporter.generateReport());
                    } else {
                        System.out.println("No report available. Generate one first!");
                    }
                    break;
                case 3:
                    if (reporter != null) {
                        reporter.setReportFormat("JSON");
                        System.out.println(reporter.generateReport());
                    } else {
                        System.out.println("No report available. Generate one first!");
                    }
                    break;
                case 4:
                    if (reporter != null) {
                        reporter.setReportFormat("CSV");
                        System.out.println(reporter.generateReport());
                    } else {
                        System.out.println("No report available. Generate one first!");
                    }
                    break;
                case 5:
                    if (reporter != null) {
                        String encrypted = crypto.encrypt(reporter.generateReport());
                        System.out.println("\nEncrypted Report:\n" + encrypted);
                    } else {
                        System.out.println("No report to encrypt.");
                    }
                    break;
                case 6:
                    System.out.println("Decryption is not a primary feature of this application.");
                    break;
                case 7:
                    if (reporter != null) {
                        System.out.print("Enter filename to save: ");
                        String filename = reader.readLine();
                        reporter.saveReportToFile(filename);
                    } else {
                        System.out.println("No report available to save.");
                    }
                    break;
                case 8:
                    if (reporter != null) {
                        System.out.print("Do you think this SMS is spam? (true/false): ");
                        String judgment = reader.readLine();
                        boolean userJudgment = Boolean.parseBoolean(judgment);
                        feedback.recordFeedback(reporter, userJudgment);

                        // Create a map to hold the data
                        Map<String, Object> analysisData = new HashMap<>();
                        analysisData.put("senderId", reporter.getSenderId());
                        analysisData.put("text", reporter.getText());
                        analysisData.put("timestamp", reporter.getTimestamp());
                        analysisData.put("riskScore", reporter.getRiskScore());
                        analysisData.put("isSpam", userJudgment);

                        // Save the data to Firebase
                        fbManager.saveAnalysis(analysisData);
                    } else {
                        System.out.println("No report available for feedback.");
                    }
                    break;
                case 0:
                    System.out.println("Goodbye! Stay safe from spam!");
                    break;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        } while(choice != 0);
    }
}