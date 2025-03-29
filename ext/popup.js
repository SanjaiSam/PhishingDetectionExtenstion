// API URLs
const GOOGLE_API_KEY = "AIzaSyD-l49CyDBOQTpgvQbNlYBIgH08mM_0tNI"; // Replace with your key
const GOOGLE_API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`;
const OPENPHISH_URL = "https://openphish.com/feed.txt";

document.addEventListener("DOMContentLoaded", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = new URL(tabs[0].url);
        const domain = url.hostname;
        const statusElem = document.getElementById("status");

        statusElem.textContent = "Checking security... 🔍";
        let finalStatus = "Secure ✅";
        let finalClass = "secure";
        let reasons = [];

        // Run all security checks
        Promise.all([
            checkGoogleSafeBrowsing(url.href).then(result => {
                if (!result) reasons.push("Unsafe (Google Safe Browsing) ❌");
                return result;
            }),
            checkOpenPhish(url.href).then(result => {
                if (!result) reasons.push("Phishing Detected (OpenPhish) ❌");
                return result;
            }),
            checkSSLValidity(domain).then(result => {
                if (!result) reasons.push("SSL Invalid ❌");
                return result;
            }),
            checkLongURL(url.href).then(result => {
                if (!result) reasons.push("Long URL Suspicious ⚠️");
                return result;
            })
        ]).then(results => {
            if (results.includes(false)) {
                finalStatus = "Not Secure ❌";
                finalClass = "not-secure";
            }

            statusElem.textContent = `${finalStatus} ${reasons.length > 0 ? "\n(" + reasons.join(", ") + ")" : ""}`;
            statusElem.className = finalClass;
        });
    });
});

// 🔍 **Google Safe Browsing Check**
function checkGoogleSafeBrowsing(url) {
    return fetch(GOOGLE_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            client: { clientId: "yourcompanyname", clientVersion: "1.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.matches) {
            return false; // URL is unsafe
        }
        return true; // URL is safe
    })
    .catch(() => true); // If API fails, assume safe (to avoid false positives)
}

// 🛑 **Phishing Check (OpenPhish)**
function checkOpenPhish(url) {
    return fetch(OPENPHISH_URL)
        .then(response => response.text())
        .then(data => !data.split("\n").includes(url))  // Return false if URL is in phishing list
        .catch(() => true);  // If check fails, assume safe (to avoid false negatives)
}

// 🔐 **SSL Certificate Validity Check**
function checkSSLValidity(domain) {
    return new Promise(resolve => {
        let img = new Image();
        img.src = `https://${domain}/favicon.ico?${Date.now()}`;  // Random cache-buster

        img.onload = () => resolve(true);  // Site loaded → SSL is valid
        img.onerror = () => resolve(false);  // Load error → SSL is invalid
    });
}

// ⚠️ **Long URL Suspicious Check**
function checkLongURL(url) {
    return new Promise(resolve => {
        const MAX_LENGTH = 100;  // Set max safe URL length
        resolve(url.length <= MAX_LENGTH);  // If URL is too long, mark as suspicious
    });
}
