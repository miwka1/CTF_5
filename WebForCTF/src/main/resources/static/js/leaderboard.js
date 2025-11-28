/**
 * CTF Platform - Leaderboard Logic
 * Логика таблицы лидеров и рейтингов
 */

class CTFLeaderboard {
    constructor() {
        this.currentView = 'top3';
        this.users = [];
        this.init();
    }

    async init() {
        await this.loadLeaderboardData();
        this.initEventListeners();
        this.renderLeaderboard();
    }

    async loadLeaderboardData() {
        try {
            // Загрузка данных с сервера
            const response = await CTFUtils.fetchJSON('/api/leaderboard');
            this.users = response.users || [];

            // Если данных нет, используем моковые данные
            if (this.users.length === 0) {
                this.users = this.getMockData();
            }
        } catch (error) {
            console.error('Error loading leaderboard:', error);
            this.users = this.getMockData();
        }
    }

    getMockData() {
        return [
            { id: 1, username: 'hacker_pro', score: 1250, avatar: '👑', joined: '2024-01-15' },
            { id: 2, username: 'cyber_ninja', score: 980, avatar: '🥷', joined: '2024-02-01' },
            { id: 3, username: 'code_breaker', score: 750, avatar: '🔐', joined: '2024-01-20' },
            { id: 4, username: 'security_guru', score: 620, avatar: '🛡️', joined: '2024-02-10' },
            { id: 5, username: 'bug_hunter', score: 580, avatar: '🐛', joined: '2024-01-25' },
            { id: 6, username: 'pentester', score: 450, avatar: '🔍', joined: '2024-02-05' },
            { id: 7, username: 'crypto_master', score: 380, avatar: '🌀', joined: '2024-02-08' },
            { id: 8, username: 'web_warrior', score: 290, avatar: '🌐', joined: '2024-02-12' }
        ];
    }

    initEventListeners() {
        const toggleBtn = document.getElementById('toggleLeaderboard');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                this.toggleView();
            });
        }

        // Обновление каждые 30 секунд
        setInterval(() => {
            this.refreshData();
        }, 30000);
    }

    toggleView() {
        this.currentView = this.currentView === 'top3' ? 'full' : 'top3';
        this.renderLeaderboard();
        this.updateToggleButton();
    }

    updateToggleButton() {
        const toggleBtn = document.getElementById('toggleLeaderboard');
        const header = document.querySelector('.leaderboard-header h3');
        const widget = document.querySelector('.leaderboard-widget');

        if (toggleBtn && header && widget) {
            if (this.currentView === 'top3') {
                toggleBtn.textContent = 'Показать всех участников';
                header.textContent = '🏆 ТОП 3';
                widget.classList.remove('expanded');
            } else {
                toggleBtn.textContent = 'Показать ТОП 3';
                header.textContent = '🏆 Полный список';
                widget.classList.add('expanded');
            }
        }
    }

    renderLeaderboard() {
        const top3List = document.getElementById('leaderboardTop3');
        const fullList = document.getElementById('leaderboardFull');

        if (top3List) {
            this.renderTop3(top3List);
        }

        if (fullList) {
            this.renderFullList(fullList);
        }

        // Показываем/скрываем списки в зависимости от текущего вида
        this.updateListVisibility();
    }

    renderTop3(container) {
        const topUsers = this.users.slice(0, 3);
        container.innerHTML = '';

        if (topUsers.length === 0) {
            container.innerHTML = '<div class="no-users-message">Нет данных о пользователях</div>';
            return;
        }

        topUsers.forEach((user, index) => {
            const leaderItem = this.createLeaderItem(user, index + 1, true);
            container.appendChild(leaderItem);
        });
    }

    renderFullList(container) {
        container.innerHTML = '';

        if (this.users.length === 0) {
            container.innerHTML = '<div class="no-users-message">Нет пользователей</div>';
            return;
        }

        this.users.forEach((user, index) => {
            const leaderItem = this.createLeaderItem(user, index + 1, false);
            container.appendChild(leaderItem);
        });
    }

    createLeaderItem(user, rank, isTop3) {
        const leaderItem = document.createElement('div');
        leaderItem.className = `leader-item ${isTop3 ? 'top' : 'regular'}`;
        leaderItem.style.animationDelay = `${(rank - 1) * 0.1}s`;

        leaderItem.innerHTML = `
            <div class="leader-rank">${rank}</div>
            <div class="leader-avatar">${user.avatar || '👤'}</div>
            <div class="leader-info">
                <div class="leader-name">${CTFUtils.escapeHtml(user.username)}</div>
                <div class="leader-stats">${CTFUtils.formatScore(user.score)}</div>
            </div>
        `;

        leaderItem.addEventListener('click', () => {
            this.showUserProfile(user);
        });

        return leaderItem;
    }

    updateListVisibility() {
        const top3List = document.getElementById('leaderboardTop3');
        const fullList = document.getElementById('leaderboardFull');

        if (top3List && fullList) {
            if (this.currentView === 'top3') {
                top3List.style.display = 'flex';
                fullList.style.display = 'none';
            } else {
                top3List.style.display = 'none';
                fullList.style.display = 'flex';
            }
        }
    }

    async refreshData() {
        await this.loadLeaderboardData();
        this.renderLeaderboard();

        // Показываем уведомление о обновлении
        CTFPlatform.showNotification('Leaderboard updated', 'info');
    }

    showUserProfile(user) {
        // Временная реализация - можно расширить для показа модального окна
        console.log('User profile:', user);
        CTFPlatform.showNotification(`Viewing profile: ${user.username}`, 'info');
    }

    searchUsers(query) {
        if (!query.trim()) {
            this.renderLeaderboard();
            return;
        }

        const filteredUsers = this.users.filter(user =>
            user.username.toLowerCase().includes(query.toLowerCase())
        );

        this.renderFilteredList(filteredUsers);
    }

    renderFilteredList(users) {
        const fullList = document.getElementById('leaderboardFull');
        if (!fullList) return;

        fullList.innerHTML = '';

        if (users.length === 0) {
            fullList.innerHTML = '<div class="no-users-message">No users found</div>';
            return;
        }

        users.forEach((user, index) => {
            const leaderItem = this.createLeaderItem(user, index + 1, false);
            fullList.appendChild(leaderItem);
        });
    }

    // Сортировка пользователей по разным критериям
    sortUsers(criteria = 'score') {
        switch (criteria) {
            case 'score':
                this.users.sort((a, b) => b.score - a.score);
                break;
            case 'username':
                this.users.sort((a, b) => a.username.localeCompare(b.username));
                break;
            case 'joined':
                this.users.sort((a, b) => new Date(b.joined) - new Date(a.joined));
                break;
        }
        this.renderLeaderboard();
    }
}

// Инициализация на главной странице
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.leaderboard-widget')) {
        new CTFLeaderboard();
    }
});