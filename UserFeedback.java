package com.smishing;

public class UserFeedback {
    public void recordFeedback(Reporter r, boolean userJudgment) {
        System.out.printf("\n[Feedback] System predicted risk score: %d | User says spam = %s\n",
            r.getRiskScore(), userJudgment ? "Yes" : "No");
    }
}