/**
 * CTF Platform - Web Challenges Manager
 * Унифицированная система для всех веб-заданий
 */

class WebChallengesManager {
    constructor() {
        this.currentChallenge = null;
        this.init();
    }

    init() {
        this.initGlobalHandlers();
        this.loadChallengeProgress();
    }

    initGlobalHandlers() {
        // Обработчики для всех заданий
        document.addEventListener('click', (e) => {
            if (e.target.matches('.show-hint-btn')) {
                this.showHint(e.target.dataset.challenge);
            }
            if (e.target.matches('.validate-flag-btn')) {
                this.validateFlag(e.target.dataset.challenge);
            }
            if (e.target.matches('.show-solution-btn')) {
                this.showSolution(e.target.dataset.challenge);
            }
        });
    }

    // Универсальное модальное окно для заданий
    createChallengeModal(title, content, buttons = []) {
        const modal = document.createElement('div');
        modal.className = 'challenge-modal';
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
            backdrop-filter: blur(10px);
            animation: fadeIn 0.3s ease-out;
        `;

        const modalContent = document.createElement('div');
        modalContent.className = 'challenge-modal-content';
        modalContent.style.cssText = `
            background: linear-gradient(135deg, rgba(26, 26, 26, 0.95), rgba(40, 40, 40, 0.95));
            border: 2px solid var(--primary-color);
            border-radius: 20px;
            padding: 2.5rem;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            color: var(--text-primary);
            backdrop-filter: blur(20px);
            box-shadow: 0 25px 80px rgba(0, 255, 136, 0.3);
            animation: slideInUp 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            position: relative;
        `;

        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '&times;';
        closeBtn.style.cssText = `
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 2rem;
            cursor: pointer;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            transition: all 0.3s ease;
        `;

        closeBtn.addEventListener('mouseenter', () => {
            closeBtn.style.background = 'rgba(255, 255, 255, 0.1)';
            closeBtn.style.color = 'var(--primary-color)';
        });

        closeBtn.addEventListener('mouseleave', () => {
            closeBtn.style.background = 'none';
            closeBtn.style.color = 'var(--text-secondary)';
        });

        closeBtn.addEventListener('click', () => {
            modal.remove();
        });

        const titleElement = document.createElement('h2');
        titleElement.textContent = title;
        titleElement.style.cssText = `
            color: var(--primary-color);
            font-family: 'Orbitron', sans-serif;
            margin-bottom: 1.5rem;
            text-align: center;
            font-size: 1.8rem;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        `;

        const contentElement = document.createElement('div');
        contentElement.className = 'modal-content';
        contentElement.innerHTML = content;

        modalContent.appendChild(closeBtn);
        modalContent.appendChild(titleElement);
        modalContent.appendChild(contentElement);

        // Добавляем кнопки если есть
        if (buttons.length > 0) {
            const buttonsContainer = document.createElement('div');
            buttonsContainer.className = 'modal-buttons';
            buttonsContainer.style.cssText = `
                display: flex;
                gap: 1rem;
                justify-content: center;
                margin-top: 2rem;
                flex-wrap: wrap;
            `;

            buttons.forEach(buttonConfig => {
                const button = document.createElement('button');
                button.textContent = buttonConfig.text;
                button.className = buttonConfig.className || 'cta-btn primary';
                button.style.cssText = buttonConfig.style || '';
                
                if (buttonConfig.onClick) {
                    button.addEventListener('click', () => {
                        buttonConfig.onClick();
                        if (buttonConfig.closeModal !== false) {
                            modal.remove();
                        }
                    });
                } else {
                    button.addEventListener('click', () => modal.remove());
                }

                buttonsContainer.appendChild(button);
            });

            modalContent.appendChild(buttonsContainer);
        }

        modal.appendChild(modalContent);

        // Закрытие по клику вне модального окна
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });

        document.body.appendChild(modal);

        // Добавляем стили анимации если их нет
        if (!document.querySelector('#modal-styles')) {
            const style = document.createElement('style');
            style.id = 'modal-styles';
            style.textContent = `
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                
                @keyframes slideInUp {
                    from {
                        opacity: 0;
                        transform: translateY(30px) scale(0.9);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0) scale(1);
                    }
                }
                
                .challenge-modal-content::-webkit-scrollbar {
                    width: 8px;
                }
                
                .challenge-modal-content::-webkit-scrollbar-track {
                    background: rgba(255, 255, 255, 0.05);
                    border-radius: 4px;
                }
                
                .challenge-modal-content::-webkit-scrollbar-thumb {
                    background: var(--primary-color);
                    border-radius: 4px;
                }
            `;
            document.head.appendChild(style);
        }

        return modal;
    }

    // Универсальное окно для ввода флага
    showFlagValidationModal(challengeName) {
        const modal = this.createChallengeModal(
            '🔍 Проверка флага',
            `
                <div style="text-align: center; margin-bottom: 2rem;">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">🏴‍☠️</div>
                    <p style="color: var(--text-secondary); margin-bottom: 2rem;">
                        Введите флаг для задания <strong>${challengeName}</strong>
                    </p>
                    <div class="form-group">
                        <input type="text" 
                               id="flagInput" 
                               placeholder="CTF{...}" 
                               class="form-input"
                               style="width: 100%; padding: 1rem; font-size: 1.1rem; text-align: center;">
                    </div>
                    <div id="flagMessage" style="margin-top: 1rem;"></div>
                </div>
            `,
            [
                {
                    text: '✅ Проверить флаг',
                    className: 'cta-btn primary full-width',
                    onClick: () => this.submitFlag(challengeName),
                    closeModal: false
                },
                {
                    text: '❌ Отмена',
                    className: 'cta-btn secondary',
                    onClick: () => {}
                }
            ]
        );

        // Добавляем обработчик Enter
        const flagInput = modal.querySelector('#flagInput');
        flagInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.submitFlag(challengeName);
            }
        });

        flagInput.focus();
    }

    async submitFlag(challengeName) {
        const flagInput = document.querySelector('#flagInput');
        const flagMessage = document.querySelector('#flagMessage');
        
        if (!flagInput || !flagMessage) return;

        const flag = flagInput.value.trim();
        if (!flag) {
            flagMessage.innerHTML = '<span style="color: var(--error-color);">⚠️ Введите флаг</span>';
            return;
        }

        try {
            const response = await fetch(`/challenges/${this.getChallengeEndpoint(challengeName)}/validate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `flag=${encodeURIComponent(flag)}`
            });

            const result = await response.json();
            
            if (result.success) {
                flagMessage.innerHTML = `<span style="color: var(--primary-color);">🎉 ${result.message}</span>`;
                this.markChallengeAsSolved(challengeName);
                
                // Автоматически закрываем через 2 секунды
                setTimeout(() => {
                    const modal = document.querySelector('.challenge-modal');
                    if (modal) modal.remove();
                }, 2000);
            } else {
                flagMessage.innerHTML = `<span style="color: var(--error-color);">❌ ${result.message}</span>`;
            }
        } catch (error) {
            flagMessage.innerHTML = `<span style="color: var(--error-color);">⚠️ Ошибка проверки флага</span>`;
            console.error('Flag validation error:', error);
        }
    }

    // Универсальное окно подсказки
    async showHint(challengeName) {
        try {
            const response = await fetch(`/challenges/${this.getChallengeEndpoint(challengeName)}/hint`);
            const result = await response.json();
            
            this.createChallengeModal(
                '💡 Подсказка',
                `
                    <div style="text-align: center;">
                        <div style="font-size: 3rem; margin-bottom: 1rem;">💡</div>
                        <p style="color: var(--text-secondary); line-height: 1.6;">
                            ${result.hint || 'Подсказка не найдена'}
                        </p>
                        <div style="margin-top: 2rem; padding: 1rem; background: rgba(0, 255, 136, 0.1); border-radius: 8px;">
                            <small style="color: var(--text-secondary);">
                                ⚠️ Использование подсказки может повлиять на получение очков
                            </small>
                        </div>
                    </div>
                `,
                [
                    {
                        text: 'Понятно',
                        className: 'cta-btn primary',
                        onClick: () => {}
                    }
                ]
            );
        } catch (error) {
            console.error('Hint loading error:', error);
            CTFPlatform.showNotification('Ошибка загрузки подсказки', 'error');
        }
    }

    // Универсальное окно решения
    async showSolution(challengeName) {
        this.createChallengeModal(
            '🔧 Решение',
            `
                <div style="text-align: center;">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">🔧</div>
                    <p style="color: var(--text-secondary); margin-bottom: 2rem;">
                        Подход к решению задания <strong>${challengeName}</strong>
                    </p>
                    
                    <div style="text-align: left; background: rgba(255, 255, 255, 0.05); padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem;">
                        <h4 style="color: var(--primary-color); margin-bottom: 1rem;">Шаги решения:</h4>
                        ${this.getChallengeSolution(challengeName)}
                    </div>
                    
                    <div style="padding: 1rem; background: rgba(255, 165, 0, 0.1); border-radius: 8px;">
                        <small style="color: #ffa500;">
                            ⚠️ Просмотр решения лишает вас очков за задание
                        </small>
                    </div>
                </div>
            `,
            [
                {
                    text: 'Я понимаю',
                    className: 'cta-btn primary',
                    onClick: () => {}
                }
            ]
        );
    }

    getChallengeEndpoint(challengeName) {
        const endpoints = {
            'SQL Injection Basic': 'sqli',
            'Authentication Bypass': 'auth-bypass',
            'XSS Challenge': 'xss',
            'CSRF Challenge': 'csrf',
            'Path Traversal': 'path-traversal'
        };
        return endpoints[challengeName] || challengeName.toLowerCase().replace(' ', '-');
    }

    getChallengeSolution(challengeName) {
        const solutions = {
            'SQL Injection Basic': `
                <ol style="margin: 0; padding-left: 1.5rem; color: var(--text-secondary);">
                    <li>В поле username введите: <code>' OR '1'='1</code></li>
                    <li>Оставьте поле password пустым или введите любой текст</li>
                    <li>Нажмите Login - вы получите доступ и флаг</li>
                    <li>Альтернативные payloads: <code>' OR 1=1--</code>, <code>admin'--</code></li>
                </ol>
            `,
            'Authentication Bypass': `
                <ol style="margin: 0; padding-left: 1.5rem; color: var(--text-secondary);">
                    <li>Установите cookie: <code>document.cookie = "admin=true"</code></li>
                    <li>Или используйте URL параметр: <code>?admin=true</code></li>
                    <li>Или установите localStorage: <code>localStorage.setItem('admin', 'true')</code></li>
                    <li>Нажмите "Check Access" для получения флага</li>
                </ol>
            `,
            'XSS Challenge': `
                <ol style="margin: 0; padding-left: 1.5rem; color: var(--text-secondary);">
                    <li>Введите XSS payload в комментарий: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                    <li>Или используйте: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                    <li>После выполнения payload появится флаг</li>
                    <li>Флаг автоматически скопируется в буфер обмена</li>
                </ol>
            `,
            'CSRF Challenge': `
                <ol style="margin: 0; padding-left: 1.5rem; color: var(--text-secondary);">
                    <li>Создайте HTML страницу с формой, отправляющей запрос на /challenges/csrf/transfer</li>
                    <li>Форма должна автоматически отправляться при загрузке страницы</li>
                    <li>Используйте JavaScript для автоматической отправки POST запроса</li>
                    <li>При успешной передаче средств появится флаг</li>
                </ol>
            `,
            'Path Traversal': `
                <ol style="margin: 0; padding-left: 1.5rem; color: var(--text-secondary);">
                    <li>Введите путь: <code>../../etc/passwd</code></li>
                    <li>Или: <code>../secret/flag.txt</code></li>
                    <li>Или: <code>....//....//etc/hosts</code></li>
                    <li>При успешном доступе к /secret/flag.txt появится флаг</li>
                </ol>
            `
        };
        return solutions[challengeName] || '<p>Решение не найдено</p>';
    }

    markChallengeAsSolved(challengeName) {
        const solvedChallenges = JSON.parse(localStorage.getItem('solvedChallenges') || '{}');
        solvedChallenges[challengeName] = true;
        localStorage.setItem('solvedChallenges', JSON.stringify(solvedChallenges));
        
        // Обновляем UI если на странице категорий
        this.updateChallengeProgress();
    }

    loadChallengeProgress() {
        const solvedChallenges = JSON.parse(localStorage.getItem('solvedChallenges') || '{}');
        
        // Обновляем карточки заданий
        document.querySelectorAll('.challenge-card').forEach(card => {
            const challengeName = card.querySelector('h3').textContent;
            if (solvedChallenges[challengeName]) {
                card.classList.add('solved');
                const solvedBadge = document.createElement('span');
                solvedBadge.className = 'solved-badge';
                solvedBadge.textContent = '✅ Решено';
                card.appendChild(solvedBadge);
            }
        });
    }

    updateChallengeProgress() {
        // Можно добавить обновление прогресса в реальном времени
        console.log('Challenge progress updated');
    }
}

// Глобальные функции для использования в HTML
function showChallengeHint(challengeName) {
    if (window.webChallengesManager) {
        window.webChallengesManager.showHint(challengeName);
    }
}

function validateChallengeFlag(challengeName) {
    if (window.webChallengesManager) {
        window.webChallengesManager.showFlagValidationModal(challengeName);
    }
}

function showChallengeSolution(challengeName) {
    if (window.webChallengesManager) {
        window.webChallengesManager.showSolution(challengeName);
    }
}

// Инициализация менеджера
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname.includes('/category/web') || 
        window.location.pathname.includes('/challenges/')) {
        window.webChallengesManager = new WebChallengesManager();
    }
});