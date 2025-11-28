/**
 * CTF Platform - Path Traversal Challenge
 * Логика для Path Traversal челленджа
 */

class PathTraversalChallenge {
    constructor() {
        this.basePath = '/public/';
        this.virtualFilesystem = this.createVirtualFilesystem();
        this.init();
    }

    init() {
        this.initEventListeners();
        this.loadInitialDirectory();
    }

    initEventListeners() {
        const loadBtn = document.querySelector('button[onclick="loadFile()"]');
        const fileInput = document.getElementById('filePath');

        if (loadBtn) {
            loadBtn.addEventListener('click', () => {
                this.loadFile();
            });
        }

        if (fileInput) {
            fileInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.loadFile();
                }
            });
        }
    }

    createVirtualFilesystem() {
        return {
            '/public/': {
                type: 'directory',
                children: ['readme.txt', 'config.json', 'images/']
            },
            '/public/readme.txt': {
                type: 'file',
                content: 'Welcome to the file server!\nThis is a public readme file.\n\nFlag is located in /secret/flag.txt'
            },
            '/public/config.json': {
                type: 'file',
                content: '{\n  "server": "CTF Platform",\n  "version": "2.0",\n  "debug": false\n}'
            },
            '/public/images/': {
                type: 'directory',
                children: ['logo.png', 'background.jpg']
            },
            '/public/images/logo.png': {
                type: 'file',
                content: 'PNG image data (simulated)'
            },
            '/public/images/background.jpg': {
                type: 'file',
                content: 'JPEG image data (simulated)'
            },
            '/secret/': {
                type: 'directory',
                children: ['flag.txt', 'credentials.db']
            },
            '/secret/flag.txt': {
                type: 'file',
                content: 'CTF{PATH_TRAVERSAL_MASTER_2024}'
            },
            '/secret/credentials.db': {
                type: 'file',
                content: 'admin:supersecretpassword\nuser:weakpassword'
            },
            '/etc/': {
                type: 'directory',
                children: ['passwd', 'hosts']
            },
            '/etc/passwd': {
                type: 'file',
                content: 'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash'
            },
            '/etc/hosts': {
                type: 'file',
                content: '127.0.0.1 localhost\n127.0.1.1 ctf-platform'
            }
        };
    }

    loadFile() {
        const fileInput = document.getElementById('filePath');
        const fileContent = document.getElementById('fileContent');

        if (!fileInput || !fileContent) return;

        const path = fileInput.value.trim();
        if (!path) {
            this.showError('Please enter a file path');
            return;
        }

        // Уязвимость: отсутствует проверка path traversal
        const normalizedPath = this.normalizePath(path);
        const file = this.virtualFilesystem[normalizedPath];

        if (!file) {
            this.showError(`File not found: ${path}`);
            return;
        }

        if (file.type === 'directory') {
            this.showDirectory(normalizedPath, file);
        } else {
            this.showFile(normalizedPath, file);
        }

        // Проверяем path traversal атаку
        this.checkPathTraversal(path, normalizedPath);
    }

    normalizePath(path) {
        // Упрощенная нормализация пути (уязвимая)
        if (!path.startsWith('/')) {
            path = this.basePath + path;
        }

        // Обработка ../ (уязвимость!)
        let normalized = path;
        while (normalized.includes('/../')) {
            normalized = normalized.replace(/[^/]+\/\.\.\//, '');
        }

        // Убираем двойные слеши
        normalized = normalized.replace(/\/+/g, '/');

        // Добавляем trailing slash для директорий
        if (normalized.endsWith('/') && !this.virtualFilesystem[normalized]) {
            normalized = normalized.slice(0, -1);
        }

        return normalized;
    }

    showDirectory(path, directory) {
        const fileContent = document.getElementById('fileContent');
        fileContent.innerHTML = '';

        const header = document.createElement('h4');
        header.textContent = `Directory: ${path}`;
        fileContent.appendChild(header);

        const fileList = document.createElement('ul');
        fileList.className = 'file-list';

        directory.children.forEach(child => {
            const listItem = document.createElement('li');
            listItem.className = 'file-item';

            const fullPath = path.endsWith('/') ? path + child : path + '/' + child;
            const isDir = this.virtualFilesystem[fullPath]?.type === 'directory';

            listItem.className += isDir ? ' directory' : ' file';
            listItem.innerHTML = `
                ${isDir ? '📁' : '📄'} ${child}
                ${!isDir ? '<span class="file-size">1.2KB</span>' : ''}
            `;

            listItem.addEventListener('click', () => {
                document.getElementById('filePath').value = fullPath;
                this.loadFile();
            });

            fileList.appendChild(listItem);
        });

        fileContent.appendChild(fileList);
        fileContent.className = 'file-content';
    }

    showFile(path, file) {
        const fileContent = document.getElementById('fileContent');
        fileContent.textContent = file.content;
        fileContent.className = 'file-content success';

        // Подсветка синтаксиса для определенных типов файлов
        if (path.endsWith('.json')) {
            this.highlightJSON(fileContent);
        }
    }

    showError(message) {
        const fileContent = document.getElementById('fileContent');
        fileContent.textContent = message;
        fileContent.className = 'file-content error';
    }

    highlightJSON(element) {
        try {
            const json = JSON.parse(element.textContent);
            element.textContent = JSON.stringify(json, null, 2);
        } catch (e) {
            // Не JSON или уже отформатирован
        }
    }

    checkPathTraversal(originalPath, normalizedPath) {
        // Проверяем path traversal атаку
        const traversalPatterns = [
            /\.\.\//,
            /\/etc\//,
            /\/secret\//,
            /\/\.\.\//,
            /\/passwd/,
            /\/flag/
        ];

        const hasTraversal = traversalPatterns.some(pattern =>
            pattern.test(originalPath) || pattern.test(normalizedPath)
        );

        if (hasTraversal && normalizedPath === '/secret/flag.txt') {
            CTFPlatform.showNotification('Path traversal detected! Flag captured!', 'success');
            this.showFlag();
        } else if (hasTraversal) {
            CTFPlatform.showNotification('Path traversal attempt detected', 'warning');
        }
    }

    showFlag() {
        const flag = 'CTF{PATH_TRAVERSAL_MASTER_2024}';
        const fileBrowser = document.querySelector('.file-browser');
        if (!fileBrowser) return;

        const flagElement = document.createElement('div');
        flagElement.className = 'message success';
        flagElement.innerHTML = `
            🎉 Path Traversal Successful!<br>
            <strong>Flag: ${flag}</strong><br>
            <small>Vulnerability: Lack of path sanitization</small>
        `;

        flagElement.addEventListener('click', () => {
            CTFUtils.copyToClipboard(flag);
        });

        fileBrowser.appendChild(flagElement);

        CTFUtils.copyToClipboard(flag);
    }

    loadInitialDirectory() {
        const fileInput = document.getElementById('filePath');
        if (fileInput) {
            fileInput.value = this.basePath;
            this.loadFile();
        }
    }

    // Методы для демонстрации уязвимостей
    demonstrateTraversal() {
        const examples = [
            '../../etc/passwd',
            '../secret/flag.txt',
            '....//....//....//etc/hosts',
            '/public/../../secret/credentials.db'
        ];

        console.log('Path Traversal Examples:');
        examples.forEach(example => {
            console.log(`- ${example} -> ${this.normalizePath(example)}`);
        });

        CTFPlatform.showNotification('Traversal examples logged to console', 'info');
    }

    resetChallenge() {
        const fileInput = document.getElementById('filePath');
        const fileContent = document.getElementById('fileContent');

        if (fileInput) fileInput.value = this.basePath;
        if (fileContent) {
            fileContent.textContent = '';
            fileContent.className = 'file-content';
        }

        this.loadInitialDirectory();
        CTFPlatform.showNotification('File browser reset', 'info');
    }
}

// Глобальная функция для обратной совместимости
function loadFile() {
    if (window.pathTraversalChallenge) {
        window.pathTraversalChallenge.loadFile();
    }
}

// Инициализация на странице Path Traversal
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname.includes('/path-traversal')) {
        window.pathTraversalChallenge = new PathTraversalChallenge();
    }
});