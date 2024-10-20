document.addEventListener('DOMContentLoaded', () => {
    const newConversationBtn = document.querySelector('.new-conversation');
    const conversationList = document.querySelector('.conversation-list');
    const messagesContainer = document.getElementById('messages');
    const darkModeToggle = document.getElementById('darkModeToggle');
    const modeText = document.getElementById('modeText');
    const analysisTypeSelect = document.getElementById('analysisType');
    const languageSelect = document.getElementById('languageSelect');
    const codeInput = document.getElementById('codeInput');
    const githubInputContainer = document.getElementById('githubInputContainer');
    const githubInput = document.getElementById('githubInput');
    const analyzeButton = document.getElementById('analyzeButton');
    const inputSection = document.querySelector('.input-section');
    const outputSection = document.querySelector('.output-section');

    let conversations = [];
    let activeConversationId = null;
    let conversationCounter = 1;

    function createNewConversation() {
        const id = Date.now().toString();
        const conversation = {
            id: id,
            name: `Conversation ${conversationCounter}`,
            messages: []
        };
        conversations.push(conversation);
        conversationCounter++;
        renderConversationList();
        switchToConversation(id);
    }

    function renderConversationList() {
        conversationList.innerHTML = '';
        conversations.forEach(conv => {
            const convElement = document.createElement('button');
            convElement.className = 'conversation';
            convElement.textContent = conv.name;
            convElement.dataset.id = conv.id;
            convElement.addEventListener('click', () => switchToConversation(conv.id));
            conversationList.appendChild(convElement);
        });
    }

    function switchToConversation(id) {
        activeConversationId = id;
        updateActiveConversationUI();
        renderMessages();
    }

    function updateActiveConversationUI() {
        document.querySelectorAll('.conversation').forEach(el => {
            el.classList.toggle('active', el.dataset.id === activeConversationId);
        });
    }

    function renderMessages() {
        const activeConversation = conversations.find(c => c.id === activeConversationId);
        if (!activeConversation) return;

        messagesContainer.innerHTML = '';
        activeConversation.messages.forEach(msg => {
            const msgElement = document.createElement('div');
            msgElement.className = `message ${msg.sender}`;
            msgElement.textContent = msg.content;
            messagesContainer.appendChild(msgElement);
        });
    }

    function addMessageToActiveConversation(content, sender) {
        const activeConversation = conversations.find(c => c.id === activeConversationId);
        if (!activeConversation) return;

        activeConversation.messages.push({ content, sender });
        renderMessages();
    }

    function toggleInputSection() {
        inputSection.classList.toggle('collapsed');
        outputSection.classList.toggle('expanded');
    }

    newConversationBtn.addEventListener('click', createNewConversation);

    darkModeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        darkModeToggle.textContent = document.body.classList.contains('dark-mode') ? '🌜' : '🌞';
        modeText.textContent = document.body.classList.contains('dark-mode') ? 'Dark Mode' : 'Light Mode';
    });

    analysisTypeSelect.addEventListener('change', () => {
        if (analysisTypeSelect.value === 'github') {
            codeInput.style.display = 'none';
            githubInputContainer.style.display = 'block';
        } else {
            codeInput.style.display = 'block';
            githubInputContainer.style.display = 'none';
        }
    });

    analyzeButton.addEventListener('click', () => {
        let content;
        if (analysisTypeSelect.value === 'github') {
            content = `Analyzing GitHub repository: ${githubInput.value}`;
        } else {
            content = `Analyzing code:\n${codeInput.value}`;
        }
        addMessageToActiveConversation(content, 'user');
        toggleInputSection(); // Collapse input section
        // Here you would typically send the data to your backend for analysis
        // For now, we'll just add a mock response
        setTimeout(() => {
            addMessageToActiveConversation('Analysis complete. No vulnerabilities found.', 'bot');
        }, 1000);
    });

    // Create an initial conversation
    createNewConversation();
});
