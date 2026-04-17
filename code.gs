const EXTENSION_TOKEN = "TheSunIsPurpleIsIt!";

function doPost(e) {
  try {
    const requestData = JSON.parse(e.postData.contents);
    if (requestData.token !== EXTENSION_TOKEN) {
      return ContentService.createTextOutput(JSON.stringify({ error: "Unauthorized" })).setMimeType(ContentService.MimeType.JSON);
    }

    const userGroqKey = String(requestData.groqKey || "").trim();
    const userVtKey = String(requestData.vtKey || "").trim();

    const websiteUrl = requestData.url || "";
    const websiteText = requestData.text || "";

    let bareDomain = "";
    try {
      bareDomain = websiteUrl.replace(/^https?:\/\//i, '').split('/')[0].replace(/^www\./i, '');
    } catch (err) {
      bareDomain = websiteUrl; 
    }

    let vtScoreStr = "Unknown";
    let domainAgeStr = "Unknown";
    let vtBadEngines = 0;
    let ageInDays = 9999; 

    if (!bareDomain) {
      vtScoreStr = "No URL Provided";
      domainAgeStr = "Frontend Error";
    } else {
      const vtUrl = "https://www.virustotal.com/api/v3/domains/" + bareDomain;
      const vtOptions = { method: "get", headers: { "x-apikey": userVtKey }, muteHttpExceptions: true };
      
      try {
        const vtResponse = UrlFetchApp.fetch(vtUrl, vtOptions);
        const responseCode = vtResponse.getResponseCode();
        
        if (responseCode === 200) {
          const attrs = JSON.parse(vtResponse.getContentText()).data.attributes;

          if (attrs.last_analysis_stats) {
            const stats = attrs.last_analysis_stats;
            vtBadEngines = stats.malicious + stats.suspicious;
            const total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected + stats.timeout;
            vtScoreStr = `${vtBadEngines} / ${total} engines`;
          }

          if (attrs.creation_date) {
            const ageInMs = Date.now() - (attrs.creation_date * 1000);
            ageInDays = Math.floor(ageInMs / (1000 * 60 * 60 * 24));
            
            if (ageInDays < 30) domainAgeStr = ageInDays + " days";
            else if (ageInDays < 365) domainAgeStr = Math.floor(ageInDays / 30) + " months";
            else domainAgeStr = Math.floor(ageInDays / 365) + " years";
          }
        } else if (responseCode === 404) {
          vtScoreStr = "Unscanned (Ghost)";
          domainAgeStr = "Unknown to VT";
          ageInDays = 0; 
        } else if (responseCode === 401) {
          vtScoreStr = "VT Key Invalid";
          domainAgeStr = "Auth Error";
        } else {
          domainAgeStr = "API Error";
        }
      } catch (e) {
        vtScoreStr = "Fetch Failed";
        domainAgeStr = String(e.message).substring(0, 15); 
      }
    }

    if (vtBadEngines > 0) {
      const instantResponse = {
        success: true,
        risk_level: "dangerous",
        title: "Blacklisted by VirusTotal",
        reason: `DANGER: ${vtBadEngines} security vendors flagged this domain as malicious. Leave immediately.`,
        summary: "AI scanning was skipped because the domain is already a known threat.",
        vt_score: vtScoreStr,
        domain_age: domainAgeStr
      };
      return ContentService.createTextOutput(JSON.stringify(instantResponse)).setMimeType(ContentService.MimeType.JSON);
    }

    let aiResult = { risk_level: "safe", title: "Safe", reason: "Analysis successful.", summary: "No summary." };
    
    if (websiteText.length > 50) {
      const groqUrl = "https://api.groq.com/openai/v1/chat/completions";
      const payload = {
        model: "llama-3.3-70b-versatile",
        response_format: { type: "json_object" },
        messages: [
          { 
            role: "system", 
            content: `You are a cybersecurity web analyst. Analyze the provided webpage text to detect phishing, scams, or social engineering. 
            DO NOT flag technical documentation, code repositories, or API dashboards as dangerous. 
            Output ONLY a valid JSON object with exactly these 4 keys:
            1. "risk_level": must be exactly "safe", "warning", or "dangerous".
            2. "title": a short classification (e.g., "Safe Website", "Suspicious Language", "Phishing Attempt").
            3. "reason": a 1-sentence explanation of your risk assessment.
            4. "summary": 1 short bullet point summarizing the actual content.`
          },
          { role: "user", content: websiteText }
        ],
        temperature: 0.1
      };

      const options = {
        method: "post",
        headers: { "Authorization": "Bearer " + userGroqKey, "Content-Type": "application/json" },
        payload: JSON.stringify(payload),
        muteHttpExceptions: true
      };

      try {
        const response = UrlFetchApp.fetch(groqUrl, options);
        const jsonResponse = JSON.parse(response.getContentText());

        let rawContent = jsonResponse.choices[0].message.content;

        rawContent = rawContent.replace(/```json/g, "").replace(/```/g, "").trim();

        const parsedAnalysis = JSON.parse(rawContent);

        if (parsedAnalysis.risk_level) {
          
          let extractedSummary = "No summary provided.";
          if (parsedAnalysis.summary) {
            if (typeof parsedAnalysis.summary === 'object') {
              extractedSummary = parsedAnalysis.summary.content || 
                                 parsedAnalysis.summary.text || 
                                 Object.values(parsedAnalysis.summary)[0] || 
                                 "Summary format error.";
            } else {
              extractedSummary = String(parsedAnalysis.summary);
            }
          }

          aiResult = {
            risk_level: String(parsedAnalysis.risk_level),
            title: String(parsedAnalysis.title || "AI Analysis"),
            reason: String(parsedAnalysis.reason || "Checked via LLM."),
            summary: String(extractedSummary)
          };
        }
      } catch (e) {
        aiResult = {
          risk_level: "warning",
          title: "Analysis Error",
          reason: "The AI scanner encountered a formatting error or timeout.",
          summary: "Could not generate summary due to technical error: " + e.message
        };
        console.error("Groq Error: ", e);
      }
    }

    if (aiResult.risk_level === "safe" && ageInDays < 30) {
      aiResult.risk_level = "warning";
      aiResult.title = "Brand New Domain";
      aiResult.reason = `WARNING: This domain is only ${ageInDays} days old (or unknown). Scammers frequently use new domains to evade detection. Proceed with caution.`;
    }

    const responsePayload = {
  success: true,
  risk_level: aiResult.risk_level || "unknown",
  title: aiResult.title || "Unknown",
  reason: aiResult.reason || "No reason provided.",
  summary: typeof aiResult.summary === 'object' ? JSON.stringify(aiResult.summary) : String(aiResult.summary),
  vt_score: vtScoreStr,
  domain_age: domainAgeStr
};

    return ContentService.createTextOutput(JSON.stringify(responsePayload)).setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({ success: false, error: String(error) })).setMimeType(ContentService.MimeType.JSON);
  }
}
