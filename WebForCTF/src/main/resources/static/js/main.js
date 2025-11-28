/**
 * CTF Platform - Main JavaScript
 * Инициализация приложения и общая логика
 */

class CTFPlatform {
    constructor() {
        this.currentPage = window.location.pathname;
        this.init();
    }

    init() {
        console.log('🚀 CTF Platform initialized on:', this.currentPage);
        this.initNavigation();
        this.initTheme();
        this.initParticles();
        this.initScrollEffects();
        this.initEventListeners();
        this.initPageSpecific();
    }

    initNavigation() {
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.nav-link');

        console.log('Current path:', currentPath);
        console.log('Nav links found:', navLinks.length);

        navLinks.forEach(link => {
            const linkPath = link.getAttribute('href');
            const isLoginBtn = link.classList.contains('login-btn');

            link.classList.remove('active');

            if (isLoginBtn) {
                if (currentPath === '/auth') {
                    link.classList.add('active');
                }
            } else if (linkPath) {
                // Основная логика для обычных ссылок
                if (currentPath === linkPath) {
                    link.classList.add('active');
                }
                // Логика для категорий
                else if (currentPath.startsWith('/category/') && linkPath === currentPath) {
                    link.classList.add('active');
                }
                // Логика для челленджей
                else if (currentPath.startsWith('/challenges/') && linkPath === currentPath) {
                    link.classList.add('active');
                }
                // Главная страница
                else if (currentPath === '/' && linkPath === '/') {
                    link.classList.add('active');
                }
                // Пользователи
                else if (currentPath === '/users' && linkPath === '/users') {
                    link.classList.add('active');
                }
            }

            // Добавляем обработчик клика для отладки
            link.addEventListener('click', (e) => {
                console.log('Navigation click:', linkPath, '->', currentPath);
            });
        });
    }

    initTheme() {
        const savedTheme = localStorage.getItem('ctf-theme');
        if (savedTheme) {
            document.documentElement.setAttribute('data-theme', savedTheme);
        }
    }

    initParticles() {
        const particlesContainer = document.querySelector('.particles');
        if (!particlesContainer) return;

        // Очищаем существующие частицы
        particlesContainer.innerHTML = '';

        const particleCount = 8;
        for (let i = 0; i < particleCount; i++) {
            this.createParticle(particlesContainer, i);
        }
    }

    createParticle(container, index) {
        const particle = document.createElement('div');
        particle.className = 'particle';

        const size = Math.random() * 6 + 2;
        const posX = Math.random() * 100;
        const posY = Math.random() * 100;
        const delay = Math.random() * 5;
        const duration = Math.random() * 10 + 5;

        Object.assign(particle.style, {
            width: `${size}px`,
            height: `${size}px`,
            top: `${posY}%`,
            left: `${posX}%`,
            animationDelay: `${delay}s`,
            animationDuration: `${duration}s`,
            background: index % 3 === 0 ? 'var(--primary-color)' :
                       index % 3 === 1 ? 'var(--secondary-color)' : 'var(--accent-color)'
        });

        container.appendChild(particle);
    }

    initScrollEffects() {
        const background = document.querySelector('.background');
        if (background) {
            // Удаляем старые обработчики
            background._mouseMoveHandler && document.removeEventListener('mousemove', background._mouseMoveHandler);

            background._mouseMoveHandler = (e) => {
                const x = e.clientX / window.innerWidth;
                const y = e.clientY / window.innerHeight;
                background.style.transform = `translate(${x * 20}px, ${y * 20}px)`;
            };

            window.addEventListener('mousemove', background._mouseMoveHandler);
        }

        // Плавная прокрутка для якорных ссылок
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });
    }

    initEventListeners() {
        // Обработка кликов по карточкам категорий
        document.addEventListener('click', (e) => {
            const card = e.target.closest('.category-card');
            if (card && card.onclick) {
                e.preventDefault();
                eval(card.onclick);
                return;
            }

            const challengeCard = e.target.closest('.challenge-card');
            if (challengeCard && challengeCard.getAttribute('data-href')) {
                e.preventDefault();
                window.location.href = challengeCard.getAttribute('data-href');
                return;
            }
        });

        // Обработка навигации в выпадающем меню
        document.querySelectorAll('.dropdown-content .nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                console.log('Dropdown navigation:', link.getAttribute('href'));
                // Позволяем браузеру обработать переход normally
            });
        });
    }

    initPageSpecific() {
        const path = window.location.pathname;

        console.log('Initializing page:', path);

        if (path === '/') {
            this.initHomePage();
        } else if (path === '/users') {
            this.initUsersPage();
        } else if (path.includes('/category/')) {
            this.initCategoryPage();
        } else if (path === '/auth') {
            this.initAuthPage();
        } else if (path.includes('/challenges/')) {
            this.initChallengePage();
        }
    }

    initHomePage() {
        console.log('Initializing home page');
        this.initTerminal();
        this.initLeaderboard();
        this.initCategoryCards();
    }

    initTerminal() {
        const terminalBody = document.querySelector('.terminal-body');
        if (!terminalBody) return;

        const messages = [
            "> Scanning network infrastructure...",
            "> Firewall detected: BYPASSING...",
            "> Access granted to mainframe...",
            "> Loading exploit database...",
            "> System fully operational...",
            "> Welcome, hacker. Ready for challenges?"
        ];

        let currentMessage = 0;
        let currentChar = 0;
        let isDeleting = false;
        const typingSpeed = 50;

        const typeWriter = () => {
            if (currentMessage < messages.length) {
                const currentText = messages[currentMessage];

                if (!isDeleting && currentChar <= currentText.length) {
                    terminalBody.innerHTML = this.getCurrentText(messages, currentMessage) +
                                           currentText.substring(0, currentChar) +
                                           '<span class="blink">|</span>';
                    currentChar++;
                    setTimeout(typeWriter, typingSpeed);
                } else if (isDeleting && currentChar >= 0) {
                    terminalBody.innerHTML = this.getCurrentText(messages, currentMessage) +
                                           currentText.substring(0, currentChar) +
                                           '<span class="blink">|</span>';
                    currentChar--;
                    setTimeout(typeWriter, typingSpeed / 2);
                } else {
                    isDeleting = !isDeleting;
                    if (!isDeleting) {
                        currentMessage++;
                        currentChar = 0;
                    }
                    setTimeout(typeWriter, typingSpeed * 10);
                }
            } else {
                terminalBody.innerHTML = this.getCurrentText(messages, currentMessage) +
                                       '<span class="blink">_</span>';
            }
        };

        setTimeout(typeWriter, 1000);
    }

    getCurrentText(messages, currentMessage) {
        let text = '';
        for (let i = 0; i < currentMessage; i++) {
            text += messages[i] + '<br>';
        }
        return text;
    }

    initLeaderboard() {
        const toggleBtn = document.getElementById('toggleLeaderboard');
        if (toggleBtn) {
            // Удаляем старые обработчики
            toggleBtn._clickHandler && toggleBtn.removeEventListener('click', toggleBtn._clickHandler);

            toggleBtn._clickHandler = () => {
                const top3List = document.getElementById('leaderboardTop3');
                const fullList = document.getElementById('leaderboardFull');
                const widget = document.querySelector('.leaderboard-widget');
                const header = document.querySelector('.leaderboard-header h3');

                if (top3List.style.display !== 'none') {
                    top3List.style.display = 'none';
                    fullList.style.display = 'flex';
                    header.textContent = '🏆 Полный список';
                    toggleBtn.textContent = 'Показать ТОП 3';
                    widget.classList.add('expanded');

                    if (fullList.children.length === 0) {
                        this.generateFullLeaderboard();
                    }
                } else {
                    top3List.style.display = 'flex';
                    fullList.style.display = 'none';
                    header.textContent = '🏆 ТОП 3';
                    toggleBtn.textContent = 'Показать всех участников';
                    widget.classList.remove('expanded');
                }
            };

            toggleBtn.addEventListener('click', toggleBtn._clickHandler);
        }

        this.generateTop3Leaderboard();
    }

    generateTop3Leaderboard() {
        const top3List = document.getElementById('leaderboardTop3');
        if (!top3List) return;

        const mockUsers = [
            { username: 'hacker_pro', score: 1250 },
            { username: 'cyber_ninja', score: 980 },
            { username: 'code_breaker', score: 750 }
        ];

        top3List.innerHTML = '';

        mockUsers.forEach((user, index) => {
            const leaderItem = document.createElement('div');
            leaderItem.className = `leader-item ${index >= 3 ? 'regular' : ''}`;
            leaderItem.style.animationDelay = `${index * 0.2}s`;

            leaderItem.innerHTML = `
                <div class="leader-rank">${index + 1}</div>
                <div class="leader-info">
                    <div class="leader-name">${user.username}</div>
                    <div class="leader-stats">${user.score} pts</div>
                </div>
            `;

            leaderItem.addEventListener('click', function() {
                this.style.transform = 'scale(0.95)';
                setTimeout(() => {
                    this.style.transform = '';
                }, 150);
            });

            top3List.appendChild(leaderItem);
        });
    }

    generateFullLeaderboard() {
        const fullList = document.getElementById('leaderboardFull');
        if (!fullList) return;

        const mockUsers = [
            { name: 'hacker_pro', points: 1250 },
            { name: 'cyber_ninja', points: 980 },
            { name: 'code_breaker', points: 750 },
            { name: 'security_guru', points: 620 },
            { name: 'bug_hunter', points: 580 },
            { name: 'pentester', points: 450 },
            { name: 'crypto_master', points: 380 },
            { name: 'web_warrior', points: 290 }
        ];

        fullList.innerHTML = '';

        mockUsers.forEach((user, index) => {
            const leaderItem = document.createElement('div');
            leaderItem.className = 'leader-item';
            leaderItem.style.animationDelay = `${index * 0.1}s`;

            leaderItem.innerHTML = `
                <div class="leader-rank">${index + 1}</div>
                <div class="leader-info">
                    <div class="leader-name">${user.name}</div>
                    <div class="leader-stats">${user.points} pts</div>
                </div>
            `;

            fullList.appendChild(leaderItem);
        });
    }

    initCategoryCards() {
        const cards = document.querySelectorAll('.category-card, .challenge-card');
        cards.forEach(card => {
            // Удаляем старые обработчики
            card._mouseEnterHandler && card.removeEventListener('mouseenter', card._mouseEnterHandler);
            card._mouseLeaveHandler && card.removeEventListener('mouseleave', card._mouseLeaveHandler);

            card._mouseEnterHandler = () => {
                card.style.transform = 'translateY(-10px)';
            };
            card._mouseLeaveHandler = () => {
                card.style.transform = 'translateY(0)';
            };

            card.addEventListener('mouseenter', card._mouseEnterHandler);
            card.addEventListener('mouseleave', card._mouseLeaveHandler);
        });
    }

    initUsersPage() {
        console.log('Initializing users page');
    }

    initCategoryPage() {
        console.log('Initializing category page');
        this.initCategoryCards();
    }

    initAuthPage() {
        console.log('Initializing auth page');
    }

    initChallengePage() {
        console.log('Initializing challenge page');
    }

    // Метод для очистки (на случай переиспользования)
    destroy() {
        // Очищаем все обработчики событий
        const background = document.querySelector('.background');
        if (background && background._mouseMoveHandler) {
            document.removeEventListener('mousemove', background._mouseMoveHandler);
        }

        // Можно добавить очистку других обработчиков при необходимости
    }
}

// Глобальная инициализация
let ctfPlatformInstance = null;

function initializeCTFPlatform() {
    if (ctfPlatformInstance) {
        ctfPlatformInstance.destroy();
    }
    ctfPlatformInstance = new CTFPlatform();
}

// Инициализация при загрузке DOM
document.addEventListener('DOMContentLoaded', initializeCTFPlatform);

// Re-initialize when navigating (для SPA-like поведения)
window.addEventListener('popstate', initializeCTFPlatform);

// Утилиты
window.CTFPlatform = {
    showNotification: (message, type = 'info') => {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;

        Object.assign(notification.style, {
            position: 'fixed',
            top: '100px',
            right: '20px',
            padding: '1rem 1.5rem',
            borderRadius: '8px',
            background: 'var(--background-card)',
            border: `1px solid var(--${type}-color)`,
            boxShadow: '0 5px 20px rgba(0, 0, 0, 0.3)',
            zIndex: '10000',
            animation: 'slideIn 0.3s ease-out'
        });

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 3000);
    },

    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};