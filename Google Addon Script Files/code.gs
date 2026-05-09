/**
 * Main entry point triggered when an email is opened.
 */
function onGmailMessageOpen(e) {
  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  var messageId = e.gmail.messageId;
  var message = GmailApp.getMessageById(messageId);
  
  // Extract Authentication-Results header
  var rawContent = message.getRawContent();
  var authHeaderMatch = rawContent.match(/Authentication-Results:([\s\S]*?)(?=\r?\n[^\s\t])/i);
  var authResults = authHeaderMatch ? authHeaderMatch[1].replace(/\s+/g, ' ') : "";

  // Build payload
  var payload = {
    "subject": message.getSubject(),
    "sender_email": message.getFrom(),
    "body": message.getPlainBody(),
    "headers": {
      "Authentication-Results": authResults
    },
    "attachments": getAttachmentInfo(message)
  };

  return callMaliciousScorerAPI(payload);
}

/**
 * Extracts attachment metadata.
 */
function getAttachmentInfo(message) {
  var attachments = message.getAttachments();
  if (!attachments || attachments.length === 0) return null;

  return attachments.map(function(att) {
    var bytes = att.getBytes();
    var hash = computeSHA256(bytes);
    return {
      "filename": att.getName(),
      "mime_type": att.getContentType(),
      "sha256": hash,
      "size_bytes": bytes.length
    };
  });
}

/**
 * Computes SHA-256 hash of file bytes.
 */
function computeSHA256(bytes) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest.map(function(b) {
    return ("0" + (b & 0xFF).toString(16)).slice(-2);
  }).join("");
}

/**
 * Communicates with the FastAPI backend via ngrok.
 */
function callMaliciousScorerAPI(payload) {
  var BACKEND_URL = "https://undertow-sincere-nugget.ngrok-free.dev/analyze"; 
  
  var options = {
    "method": "post",
    "contentType": "application/json",
    "headers": {
      "ngrok-skip-browser-warning": "true"
    },
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true
  };

  try {
    var response = UrlFetchApp.fetch(BACKEND_URL, options);
    var responseText = response.getContentText();
    var data = JSON.parse(responseText);
    
    if (response.getResponseCode() !== 200) {
      return createErrorCard("API Error: " + response.getResponseCode());
    }
    
    return createResultCard(data);
  } catch (err) {
    Logger.log("Error: " + err);
    return createErrorCard("Connection Error: Ensure ngrok and FastAPI are running. Details: " + err);
  }
}

/**
 * Builds the main UI Card with verdict, summary, and detailed breakdown.
 */
function createResultCard(data) {
  var icon = data.verdict === "Malicious" ? "🚫" : (data.verdict === "Suspicious" ? "⚠️" : "✅");
  var color = data.verdict === "Malicious" ? "#D32F2F" : (data.verdict === "Suspicious" ? "#F57C00" : "#388E3C");
  
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(icon + " " + data.verdict)
      .setSubtitle("Overall Score: " + data.score + "/100"));

  // Summary section
  var summarySection = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText("<b>Summary:</b><br>" + data.summary));
  card.addSection(summarySection);

  // Detailed breakdown section
  var detailedSection = CardService.newCardSection()
    .setHeader("📊 Component Analysis");

  // Add each analyzer
  if (data.details && data.details.length > 0) {
    data.details.forEach(function(detail) {
      var analyzerName = formatAnalyzerName(detail.analyzer);
      var riskLevel = detail.score > (detail.max_score * 0.5) ? "HIGH RISK ❌" : "LOW RISK ✅";
      var riskColor = detail.score > (detail.max_score * 0.5) ? "#D32F2F" : "#388E3C";
      
      // Main row for analyzer
      var rowText = "<b>" + analyzerName + "</b> | Score: " + detail.score + "/" + detail.max_score + 
                    " | <font color='" + riskColor + "'>" + riskLevel + "</font>";
      detailedSection.addWidget(CardService.newTextParagraph().setText(rowText));
      
      // Add findings if any
      if (detail.findings && detail.findings.length > 0) {
        var findingsText = "";
        detail.findings.forEach(function(finding) {
          findingsText += "• " + finding + "\n";
        });
        detailedSection.addWidget(CardService.newTextParagraph()
          .setText("<i>" + findingsText.trim() + "</i>"));
      }
      
      // Add spacer between components
      detailedSection.addWidget(CardService.newTextParagraph().setText(""));
    });
  }

  card.addSection(detailedSection);

  // Key risks section
  var highRiskItems = data.details.filter(function(d) {
    return d.score > (d.max_score * 0.5);
  });
  
  if (highRiskItems.length > 0) {
    var risksSection = CardService.newCardSection()
      .setHeader("⚠️ Key Risks");
    
    highRiskItems.forEach(function(item) {
      if (item.findings && item.findings.length > 0) {
        risksSection.addWidget(CardService.newTextParagraph()
          .setText("<b>" + formatAnalyzerName(item.analyzer) + ":</b>\n" + 
                   item.findings.join("\n")));
      }
    });
    
    card.addSection(risksSection);
  }

  return card.build();
}

/**
 * Formats analyzer name from snake_case to Title Case.
 */
function formatAnalyzerName(name) {
  return name
    .split('_')
    .map(function(word) {
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    })
    .join(' ');
}

/**
 * Fallback UI for errors.
 */
function createErrorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("⚠️ Error"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(message)))
    .build();
}