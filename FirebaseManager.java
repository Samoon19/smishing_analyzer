package com.smishing;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map;

public class FirebaseManager {
    private final FirebaseDatabase database;

    public FirebaseManager(String databaseUrl, String serviceAccountKeyPath) {
        try {
            FileInputStream serviceAccount = new FileInputStream(serviceAccountKeyPath);

            FirebaseOptions options = FirebaseOptions.builder()
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                    .setDatabaseUrl(databaseUrl)
                    .build();

            FirebaseApp.initializeApp(options);
            database = FirebaseDatabase.getInstance();

        } catch (IOException e) {
            throw new RuntimeException("Error initializing Firebase: " + e.getMessage());
        }
    }

    public void saveAnalysis(Map<String, Object> data) {
        DatabaseReference ref = database.getReference("reports");
        DatabaseReference newReportRef = ref.push();
        newReportRef.setValueAsync(data);
        System.out.println("Analysis data saved to Firebase.");
    }
}