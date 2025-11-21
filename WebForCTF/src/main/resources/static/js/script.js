/**
 * CTF Platform - Main JavaScript functionality :)
 * Enhanced and optimized version
 */

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded - checking resources...');

    if (typeof initializePlatform === 'function') {
        console.log('✅ JavaScript functions loaded');
        try {
            initializePlatform();
        } catch (error) {
            console.error('❌ Error initializing platform:', error);
            initializeBasicEffects();
        }
    } else {
        console.error('❌ JavaScript functions not found - loading fallback');
        initializeBasicEffects();
    }
});

function generateTop3Leaderboard() {
    const top3List = document.getElementById('leaderboardTop3');
    if (!top3List) return;

    top3List.innerHTML = '';

    fetch('http://localhost:8081/top3')
        .then(response => response.json())
        .then(users => {

            const topUsers = users.slice(0, 3);


            if (topUsers.length === 0) {
                top3List.innerHTML = '<div class="no-users-message">Нет данных о пользователях</div>';
                return;
            }


            topUsers.forEach((user, index) => {
                const leaderItem = document.createElement('div');
                leaderItem.className = `leader-item ${index >= 3 ? 'regular' : ''}`;
                leaderItem.style.animationDelay = `${index * 0.2}s`;

                leaderItem.innerHTML = `
                    <div class="leader-rank">${index + 1}</div>
                    <div class="leader-info">
                        <div class="leader-name">${user.username}</div>
                        <div class="leader-stats">${user.score || 0} pts</div>
                    </div>
                `;

                leaderItem.addEventListener('click', function() {
                    this.style.transform = 'scale(0.95)';
                    setTimeout(() => {
                        this.style.transform = '';
                    }, 150);
                    console.log(`Clicked on: ${user.username}`);
                });

                top3List.appendChild(leaderItem);
            });
        })
        .catch(error => {
            console.error('Error fetching top users:', error);
            top3List.innerHTML = '<div class="no-users-message">Здесь пока пусто(</div>';
        });
}

function initializeBasicEffects() {
    console.log('Initializing basic effects...');

    const particles = document.querySelectorAll('.particle');
    particles.forEach((particle, index) => {
        particle.style.animation = `float ${6 + index}s infinite ease-in-out`;
    });

    const blink = document.querySelector('.blink');
    if (blink) {
        setInterval(() => {
            blink.style.opacity = blink.style.opacity === '0.3' ? '1' : '0.3';
        }, 500);
    }

    const cards = document.querySelectorAll('.category-card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-10px)';
            card.style.boxShadow = '0 15px 30px rgba(0, 255, 136, 0.3)';
        });
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0)';
            card.style.boxShadow = '';
        });
    });

    const buttons = document.querySelectorAll('.cta-btn');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', () => {
            button.style.transform = 'translateY(-3px)';
        });
        button.addEventListener('mouseleave', () => {
            button.style.transform = 'translateY(0)';
        });
    });

    console.log('Basic effects initialized');
}

function initializePlatform() {
    console.log('Initializing platform...');

    try {
        createParticles();
        initCategoryCards();
        initButtons();
        initTerminal();
        initParallax();
        initSmoothScroll();
        initActiveNavigation();
        initPageBackground();
        initLogoClick();
        initVisualEffects();
        initLeaderboardWidget();
        initLeaderboardToggle();
        initLeaderboardScroll();
        generateTop3Leaderboard();

        console.log('Platform initialized successfully');
    } catch (error) {
        console.error('Error initializing platform:', error);
    }
}

function initScrollLock(element, widget) {
    if (!element) return;

    let isScrolling = false;
    let scrollTimeout;

    element.addEventListener('wheel', function(e) {
        if (!isScrolling) {
            isScrolling = true;
        }

        clearTimeout(scrollTimeout);
        scrollTimeout = setTimeout(() => {
            isScrolling = false;
        }, 150);

        e.stopPropagation();
        e.preventDefault();

        const scrollAmount = e.deltaY * 0.8;
        element.scrollTop += scrollAmount;

    }, { passive: false });

    let touchStartY = 0;

    element.addEventListener('touchstart', function(e) {
        touchStartY = e.touches[0].clientY;
        e.stopPropagation();
    }, { passive: true });

    element.addEventListener('touchmove', function(e) {
        if (!isScrolling) {
            isScrolling = true;
        }

        const touchY = e.touches[0].clientY;
        const deltaY = touchStartY - touchY;

        e.stopPropagation();
        e.preventDefault();

        element.scrollTop += deltaY * 1.5;
        touchStartY = touchY;

    }, { passive: false });

    element.addEventListener('touchend', function(e) {
        clearTimeout(scrollTimeout);
        scrollTimeout = setTimeout(() => {
            isScrolling = false;
        }, 150);
        e.stopPropagation();
    });

    if (widget) {
        widget.addEventListener('mouseenter', function() {
            document.body.style.overflow = 'hidden';
        });

        widget.addEventListener('mouseleave', function() {
            document.body.style.overflow = '';
        });

        widget.addEventListener('touchstart', function(e) {
            document.body.style.overflow = 'hidden';
            e.stopPropagation();
        });

        widget.addEventListener('touchend', function(e) {
            setTimeout(() => {
                document.body.style.overflow = '';
            }, 100);
            e.stopPropagation();
        });
    }
}

function initLeaderboardScroll() {
    const top3List = document.getElementById('leaderboardTop3');
    const fullList = document.getElementById('leaderboardFull');
    const widget = document.querySelector('.leaderboard-widget');

    if (top3List) initScrollLock(top3List, widget);
    if (fullList) initScrollLock(fullList, widget);
}

function initLeaderboardToggle() {
    const toggleBtn = document.getElementById('toggleLeaderboard');
    const widget = document.querySelector('.leaderboard-widget');

    if (!toggleBtn || !widget) {
        console.error('Leaderboard elements not found');
        return;
    }
    let showingFullList = false;

    toggleBtn.addEventListener('click', function() {
        showingFullList = !showingFullList;

        if (showingFullList) {
            document.getElementById('leaderboardTop3').style.display = 'none';
            document.getElementById('leaderboardFull').style.display = 'flex';
            document.querySelector('.leaderboard-header h3').textContent = '🏆 Полный список';
            this.textContent = 'Показать ТОП 3';
            this.classList.add('showing-all');
            widget.classList.add('expanded');

            const fullList = document.getElementById('leaderboardFull');
            if (fullList.children.length === 0) {
                generateFullLeaderboard();
            }
        } else {
            document.getElementById('leaderboardTop3').style.display = 'flex';
            document.getElementById('leaderboardFull').style.display = 'none';
            document.querySelector('.leaderboard-header h3').textContent = '🏆 ТОП 3';
            this.textContent = 'Показать всех участников';
            this.classList.remove('showing-all');
            widget.classList.remove('expanded');


            generateTop3Leaderboard();
        }

        console.log('Leaderboard toggled, showing full:', showingFullList);
    });

    console.log('Leaderboard toggle initialized');
}

function generateFullLeaderboard() {
    const fullList = document.getElementById('leaderboardFull');
    if (!fullList) return;

    fetch('http://localhost:8081/allNames') // эндпоинт, который отдаёт UserNamePointsDTO
        .then(response => response.json())
        .then(users => {
            fullList.innerHTML = '';

            if (!users || users.length === 0) {
                fullList.innerHTML = '<div class="no-users-message">Нет пользователей</div>';
                return;
            }

            users.forEach((user, index) => {
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
        })
        .catch(error => {
            console.error('Ошибка при получении пользователей:', error);
            fullList.innerHTML = '<div class="no-users-message">Ошибка загрузки данных</div>';
        });
}

function createParticles() {
    const particlesContainer = document.querySelector('.particles');
    if (!particlesContainer) return;

    const particleCount = 12;
    const hackerSymbols = ['💻', '🔐', '⚡', '🔍', '💥', '🌐', '🚀', '🎯', '📡', '🔒', '👻', '🛡️'];

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle hacker-particle';

        const size = Math.random() * 30 + 20;
        const posX = Math.random() * 100;
        const posY = Math.random() * 100;
        const delay = Math.random() * 5;
        const duration = Math.random() * 15 + 10;
        const symbol = hackerSymbols[Math.floor(Math.random() * hackerSymbols.length)];

        Object.assign(particle.style, {
            width: `${size}px`,
            height: `${size}px`,
            top: `${posY}%`,
            left: `${posX}%`,
            animationDelay: `${delay}s`,
            animationDuration: `${duration}s`,
            fontSize: `${size * 0.6}px`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
        });

        particle.textContent = symbol;
        particle.title = 'Hacker particle';

        particle.addEventListener('click', function() {
            createParticleExplosion(this);
        });

        particlesContainer.appendChild(particle);
    }
}

function createParticleExplosion(element) {
    const rect = element.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;

    element.remove();

    for (let i = 0; i < 8; i++) {
        const explosionParticle = document.createElement('div');
        explosionParticle.className = 'explosion-particle';
        explosionParticle.textContent = element.textContent;
        explosionParticle.style.cssText = `
            position: fixed;
            left: ${x}px;
            top: ${y}px;
            font-size: 16px;
            pointer-events: none;
            z-index: 10000;
            animation: explode 1s ease-out forwards;
            opacity: 0;
        `;

        document.body.appendChild(explosionParticle);

        setTimeout(() => {
            explosionParticle.remove();
        }, 1000);
    }

    setTimeout(createParticles, 2000);
}

function initCategoryCards() {
    const categoryCards = document.querySelectorAll('.category-card');

    categoryCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-15px) scale(1.05)';
        });

        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0) scale(1)';
        });
    });
}

function initButtons() {
    const buttons = document.querySelectorAll('.cta-btn');

    buttons.forEach(button => {
        button.addEventListener('mouseenter', () => {
            button.style.transform = 'translateY(-3px)';
        });

        button.addEventListener('mouseleave', () => {
            button.style.transform = 'translateY(0)';
        });

        button.addEventListener('click', function(e) {
            this.style.transform = 'translateY(1px)';

            setTimeout(() => {
                this.style.transform = 'translateY(-3px)';

                const href = this.getAttribute('href');
                if (href && href !== '#' && href !== 'javascript:void(0)') {
                    setTimeout(() => {
                        window.location.href = href;
                    }, 200);
                }
            }, 150);
        });
    });
}

function initTerminal() {
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

    terminalBody.innerHTML = '';

    let currentMessage = 0;
    let currentChar = 0;
    let isDeleting = false;
    let typingSpeed = 50;

    function typeWriter() {
        if (currentMessage < messages.length) {
            const currentText = messages[currentMessage];

            if (!isDeleting && currentChar <= currentText.length) {
                terminalBody.innerHTML = getCurrentText() + currentText.substring(0, currentChar) + '<span class="blink">|</span>';
                currentChar++;
                setTimeout(typeWriter, typingSpeed);
            } else if (isDeleting && currentChar >= 0) {
                terminalBody.innerHTML = getCurrentText() + currentText.substring(0, currentChar) + '<span class="blink">|</span>';
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
            terminalBody.innerHTML = getCurrentText() + '<span class="blink">_</span>';
        }
    }

    function getCurrentText() {
        let text = '';
        for (let i = 0; i < currentMessage; i++) {
            text += messages[i] + '<br>';
        }
        return text;
    }

    setTimeout(typeWriter, 1000);
}

function initParallax() {
    const background = document.querySelector('.background');
    if (!background) return;

    window.addEventListener('mousemove', (e) => {
        const x = e.clientX / window.innerWidth;
        const y = e.clientY / window.innerHeight;

        background.style.transform = `translate(${x * 20}px, ${y * 20}px)`;
    });
}

function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));

            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

function initActiveNavigation() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');

    navLinks.forEach(link => {
        link.classList.remove('active');
    });

    navLinks.forEach(link => {
        const linkPath = link.getAttribute('href');
        const isLoginBtn = link.classList.contains('login-btn');

        if (isLoginBtn) {
            if (currentPath === '/auth') {
                link.classList.add('active');
            }
        } else {
            if (currentPath === linkPath) {
                link.classList.add('active');
            }

            if (currentPath === '/' && linkPath === '/') {
                link.classList.add('active');
            }

            if (currentPath.startsWith('/category/') && linkPath === currentPath) {
                link.classList.add('active');
            }
        }
    });
}

function debounce(func, wait) {
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

function initVisualEffects() {
    const scanLine = document.createElement('div');
    scanLine.className = 'scan-line';
    document.body.appendChild(scanLine);

    setInterval(() => {
        if (Math.random() > 0.7) {
            createRandomParticleBurst();
        }
    }, 5000);
}

function createRandomParticleBurst() {
    const particlesContainer = document.querySelector('.particles');
    if (!particlesContainer) return;

    const burstCount = 3;
    for (let i = 0; i < burstCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle hacker-particle burst-particle';
        particle.textContent = ['💥', '⚡', '🌟'][Math.floor(Math.random() * 3)];

        const startX = Math.random() * 100;
        const startY = Math.random() * 100;

        Object.assign(particle.style, {
            position: 'fixed',
            left: `${startX}%`,
            top: `${startY}%`,
            fontSize: '20px',
            animation: `burstFloat 2s ease-out forwards`
        });

        document.body.appendChild(particle);

        setTimeout(() => {
            particle.remove();
        }, 2000);
    }
}

function initLeaderboardWidget() {
    const leaderItems = document.querySelectorAll('.leader-item');

    leaderItems.forEach((item, index) => {
        item.addEventListener('click', function() {
            this.style.transform = 'scale(0.95)';
            setTimeout(() => {
                this.style.transform = '';
            }, 150);

            const teamName = this.querySelector('.leader-name').textContent;
            console.log(`Clicked on: ${teamName}`);
        });

        if (index < 3) {
            item.style.animationDelay = `${index * 0.2}s`;
        }
    });
}

function initPageBackground() {
    const path = window.location.pathname;
    if (path.includes('/category/pwn')) {
        document.body.classList.add('body-pwn');
    } else if (path.includes('/category/web')) {
        document.body.classList.add('body-web');
    } else if (path.includes('/category/crypto')) {
        document.body.classList.add('body-crypto');
    } else if (path.includes('/auth')) {
        document.body.classList.add('body-auth');
    }
}

function initLogoClick() {
    const logo = document.querySelector('.logo');
    if (logo) {
        logo.addEventListener('click', function() {
            this.style.transform = 'scale(0.95)';
            setTimeout(() => {
                this.style.transform = '';
            }, 150);
        });
    }
}

function initAdditionalLeaderboardFeatures() {
    const leaderboardWidget = document.querySelector('.leaderboard-widget');
    const leaderboardContent = document.querySelector('.leaderboard-content');

    if (leaderboardWidget && leaderboardContent) {
        leaderboardWidget.addEventListener('mouseenter', function() {
            document.body.style.overflow = 'hidden';
        });

        leaderboardWidget.addEventListener('mouseleave', function() {
            document.body.style.overflow = '';
        });

        leaderboardWidget.addEventListener('touchstart', function(e) {
            document.body.style.overflow = 'hidden';
        });

        leaderboardWidget.addEventListener('touchend', function() {
            setTimeout(() => {
                document.body.style.overflow = '';
            }, 100);
        });

        function updateScrollIndicator() {
            if (leaderboardContent.scrollHeight > leaderboardContent.clientHeight) {
                leaderboardContent.classList.add('scrollable');
            } else {
                leaderboardContent.classList.remove('scrollable');
            }
        }

        leaderboardContent.addEventListener('scroll', updateScrollIndicator);
        updateScrollIndicator();
    }

    const leaderboardContentElement = document.querySelector('.leaderboard-content');

    if (leaderboardContentElement) {
        leaderboardContentElement.addEventListener('wheel', function(e) {
            e.stopPropagation();
        });

        leaderboardContentElement.addEventListener('touchmove', function(e) {
            e.stopPropagation();
        });
    }

    const leaderboardWidgetElement = document.querySelector('.leaderboard-widget');

    if (leaderboardWidgetElement) {
        leaderboardWidgetElement.addEventListener('wheel', function(e) {
            e.stopPropagation();
        }, { passive: false });

        leaderboardWidgetElement.addEventListener('touchmove', function(e) {
            e.stopPropagation();
        }, { passive: false });

        leaderboardWidgetElement.addEventListener('keydown', function(e) {
            if ([32, 33, 34, 35, 36, 38, 40].includes(e.keyCode)) {
                e.stopPropagation();
            }
        });
    }
}


const style = document.createElement('style');
style.textContent = `
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    @keyframes explode {
        0% { transform: translate(0, 0) scale(1); opacity: 1; }
        100% { transform: translate(var(--tx, 100px), var(--ty, -100px)) scale(0); opacity: 0; }
    }

    @keyframes burstFloat {
        0% { transform: translate(0, 0) scale(1); opacity: 1; }
        100% { transform: translate(var(--burst-x, 50px), var(--burst-y, -50px)) scale(0); opacity: 0; }
    }
`;
document.head.appendChild(style);


document.addEventListener('DOMContentLoaded', function() {
    initAdditionalLeaderboardFeatures();
});

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        initializePlatform,
        createParticles,
        initCategoryCards,
        initButtons,
        initTerminal,
        initParallax,
        initSmoothScroll,
        initActiveNavigation,
        initLeaderboardToggle,
        generateFullLeaderboard,
        initScrollLock
    };
}