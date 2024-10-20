document.addEventListener('DOMContentLoaded', () => {
    const analysisType = document.getElementById('analysisType');
    const codeInputSection = document.getElementById('codeInputSection');
    const githubInputSection = document.getElementById('githubInputSection');
    const codeInput = document.getElementById('codeInput');
    const githubInput = document.getElementById('githubInput');
    const analyzeButton = document.getElementById('analyzeButton');
    const results = document.getElementById('results');
    const correctedCodeSection = document.getElementById('correctedCodeSection');
    const correctedCode = document.getElementById('correctedCode');
    const copyCodeButton = document.getElementById('copyCodeButton');
    const darkModeToggle = document.getElementById('darkModeToggle');
    const body = document.body;
    const modeText = document.getElementById('modeText');
    const toggleSidebarButton = document.getElementById('toggleSidebar');
    const chatHistory = document.getElementById('chatHistory');

    analysisType.addEventListener('change', () => {
        if (analysisType.value === 'code') {
            codeInputSection.style.display = 'block';
            githubInputSection.style.display = 'none';
        } else {
            codeInputSection.style.display = 'none';
            githubInputSection.style.display = 'block';
        }
    });

    darkModeToggle.addEventListener('click', () => {
        body.classList.toggle('dark-mode');
        updateModeText();
    });

    darkModeToggle.addEventListener('mouseover', () => {
        darkModeToggle.textContent = body.classList.contains('dark-mode') ? '🌞' : '🌜';
    });

    darkModeToggle.addEventListener('mouseout', () => {
        updateDarkModeButton();
    });

    function updateDarkModeButton() {
        if (body.classList.contains('dark-mode')) {
            darkModeToggle.textContent = '🌜';
            darkModeToggle.style.backgroundColor = '#121212';
        } else {
            darkModeToggle.textContent = '🌞';
            darkModeToggle.style.backgroundColor = '#F5F5F5';
        }
    }

    function updateModeText() {
        if (body.classList.contains('dark-mode')) {
            modeText.textContent = 'Dark Mode  ';
        } else {
            modeText.textContent = 'Light Mode ';
        }
    }

    // Set initial state
    updateDarkModeButton();
    updateModeText();

    analyzeButton.addEventListener('click', async () => {
        let data;
        if (analysisType.value === 'code') {
            const code = codeInput.value.trim();
            if (!code) {
                alert('Please enter some code to analyze.');
                return;
            }
            data = { code };
        } else {
            const repoUrl = githubInput.value.trim();
            if (!repoUrl) {
                alert('Please enter a GitHub repository URL.');
                return;
            }
            data = { repoUrl };
        }

        results.innerHTML = 'Analyzing...';
        correctedCodeSection.style.display = 'none';

        try {
            const endpoint = analysisType.value === 'code' ? '/analyze_code' : '/analyze_github';
            const response = await axios.post(`http://127.0.0.1:5000${endpoint}`, data);
            results.innerHTML = formatResults(response.data.analysis, analysisType.value);
            
            if (analysisType.value === 'code') {
                correctedCode.textContent = response.data.analysis.corrected_code;
                correctedCodeSection.style.display = 'block';
                hljs.highlightBlock(correctedCode);
            }
        } catch (error) {
            console.error('Error:', error);
            results.innerHTML = `Error: ${error.response?.data?.error || error.message}`;
        }
    });

    copyCodeButton.addEventListener('click', () => {
        navigator.clipboard.writeText(correctedCode.textContent).then(() => {
            alert('Corrected code copied to clipboard!');
        });
    });

    function formatResults(analysis, type) {
        let html = '<h3>Vulnerability Analysis Results:</h3>';
        
        // Always display the detected language
        html += `<p>Detected Language: <strong>${analysis.language}</strong></p>`;
        
        html += `<p>Overall Risk: <strong class="vulnerability-${analysis.overall_risk.toLowerCase()}">${analysis.overall_risk}</strong></p>`;
        
        if (type === 'code') {
            html += '<h4>Machine Learning Analysis:</h4>';
            html += `<p>Label: ${analysis.ml_analysis.label}</p>`;
            html += `<p>Confidence Score: ${(analysis.ml_analysis.score * 100).toFixed(2)}%</p>`;
            
            html += '<h4>Rule-Based Analysis:</h4>';
            if (analysis.rule_based_analysis.length > 0) {
                html += '<ul>';
                analysis.rule_based_analysis.forEach(vuln => {
                    html += `
                        <li class="vulnerability-${vuln.risk_level.toLowerCase()}">
                            <strong>${vuln.type}</strong> (Risk Level: ${vuln.risk_level}, Severity Score: ${vuln.severity_score})<br>
                            ${vuln.description}<br>
                            <strong>Remediation:</strong> ${vuln.remediation}<br>
                            <strong>Resource:</strong> <a href="${vuln.resource}" target="_blank">Learn more</a><br>
                            <strong>Line Number:</strong> ${vuln.line_number}<br>
                            <strong>Code Snippet:</strong>
                            <pre class="code-snippet"><code>${highlightVulnerability(vuln.code_snippet, vuln.type)}</code></pre>
                        </li>
                    `;
                });
                html += '</ul>';
            } else {
                html += '<p>No known vulnerabilities detected.</p>';
            }

            html += '<h4>Diff:</h4>';
            html += `<pre><code class="diff">${analysis.diff}</code></pre>`;
        } else {
            html += `<p>Total Files: ${analysis.total_files}</p>`;
            html += `<p>Analyzed Files: ${analysis.analyzed_files}</p>`;
            
            if (analysis.vulnerabilities.length > 0) {
                html += '<h4>Vulnerabilities by File:</h4>';
                analysis.vulnerabilities.forEach(fileVuln => {
                    html += `<h5>${fileVuln.file}</h5>`;
                    html += '<ul>';
                    fileVuln.vulnerabilities.forEach(vuln => {
                        html += `
                            <li class="vulnerability-${vuln.risk_level.toLowerCase()}">
                                <strong>${vuln.type}</strong> (Risk Level: ${vuln.risk_level}, Severity Score: ${vuln.severity_score})<br>
                                ${vuln.description}<br>
                                <strong>Remediation:</strong> ${vuln.remediation}<br>
                                <strong>Resource:</strong> <a href="${vuln.resource}" target="_blank">Learn more</a><br>
                                <strong>Line Number:</strong> ${vuln.line_number}<br>
                                <strong>Code Snippet:</strong>
                                <pre class="code-snippet"><code>${highlightVulnerability(vuln.code_snippet, vuln.type)}</code></pre>
                            </li>
                        `;
                    });
                    html += '</ul>';
                });
            } else {
                html += '<p>No known vulnerabilities detected.</p>';
            }
        }
        
        return html;
    }

    function highlightVulnerability(codeSnippet, vulnType) {
        const pattern = VULNERABILITY_PATTERNS[vulnType].pattern;
        return codeSnippet.replace(new RegExp(pattern, 'gi'), match => `<span class="vulnerability-highlight">${match}</span>`);
    }

    const VULNERABILITY_PATTERNS = {
        'sql_injection': {
            'pattern': 'SELECT.*FROM.*WHERE'
        },
        'xss': {
            'pattern': '<script>.*</script>'
        },
        'command_injection': {
            'pattern': 'exec\\(|system\\(|shell_exec\\('
        },
        'path_traversal': {
            'pattern': '\\.\\.\/'
        }
    };

    document.getElementById('analyzeButton').addEventListener('click', function() {
        // Add your analysis logic here
        const analysisType = document.getElementById('analysisType').value;
        const code = document.getElementById('codeInput').value;
        const githubUrl = document.getElementById('githubInput').value;

        // Display results in the output section
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = `<p>Analyzing ${analysisType} in ${language}...</p>`;
        
        // Simulate analysis result
        setTimeout(() => {
            resultsDiv.innerHTML += `<p>Vulnerabilities found: None</p>`;
        }, 2000);
    });

    const newConversationBtn = document.querySelector('.new-conversation');
    const conversationList = document.querySelector('.conversation-list');
    const messagesContainer = document.querySelector('.messages');

    let conversationCount = 0;
    let activeConversation = null;

    newConversationBtn.addEventListener('click', () => {
        conversationCount++;
        const newConversation = document.createElement('div');
        newConversation.className = 'conversation';
        newConversation.textContent = `Conversation ${conversationCount}`;
        conversationList.appendChild(newConversation);

        newConversation.addEventListener('click', () => {
            switchConversation(newConversation);
        });

        switchConversation(newConversation);
    });

    function switchConversation(conversation) {
        if (activeConversation) {
            activeConversation.classList.remove('active');
        }
        activeConversation = conversation;
        activeConversation.classList.add('active');
        loadMessagesForConversation(activeConversation.textContent);
    }

    function loadMessagesForConversation(conversationName) {
        messagesContainer.innerHTML = `<p>Loading messages for ${conversationName}...</p>`;
        // Simulate loading messages
        setTimeout(() => {
            messagesContainer.innerHTML = `<p>No messages yet in ${conversationName}.</p>`;
        }, 500);
    }

    toggleSidebarButton.addEventListener('click', () => {
        chatHistory.classList.toggle('closed');
        chatHistory.classList.toggle('open');
    });
});
